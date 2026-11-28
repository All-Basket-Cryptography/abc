"""Lower Rust SHA3-256 digest and SHAKE256 finalization from structured LLBC."""

from dataclasses import dataclass

from llbc import (Cell, Crate, Execution, Product, Ref, Scalar, array, code, copy, function_code,
                  name, reference, require, slice_cells, uint)


RATE = 136


@dataclass(frozen=True)
class SliceRange:
    start: int | None
    end: int | None


@dataclass(frozen=True)
class PartitionedInput:
    blocks: list
    tail: list


@dataclass(frozen=True)
class LaneSymbol:
    absorbed: int
    lane: int


@dataclass(frozen=True)
class LaneByte:
    source: LaneSymbol
    offset: int


class WrapperCrate(Crate):
    def __init__(self, artifact, target, leaf, entry):
        require(artifact["has_errors"] is False, "Charon reported Rust sponge wrapper errors")
        self.data = artifact["translated"]
        self.leaf = leaf
        targets = self.data["target_information"]
        require(self.data["crate_name"] == self.leaf and self.data["options"]["start_from"] == [f"crate::{entry}"] and
                len(targets) == 1 and targets[0]["key"] == target and targets[0]["value"]["target_pointer_size"] == 8,
                "Expected the pinned x86-64 Rust sponge wrapper closure")
        self.constants = {}
        self.collect_constants(self.data)
        self.globals = {}

    def declaration(self, section, exported):
        matches = [decl for decl in self.data[section] if decl and name(decl) == (self.leaf, exported)]
        require(len(matches) == 1, f"Expected one sponge wrapper declaration named {exported}")
        return matches[0]


class WrapperExecution(Execution):
    def __init__(self, crate, locals_):
        super().__init__(crate, locals_)
        self.chunks = 0
        self.absorptions = []
        self.encoding_calls = []

    def rvalue(self, node):
        match node:
            case {"Aggregate": [{"Adt": [{"id": type_id}, None, None]}, operands]} if operands:
                type_name = name(self.crate.data["type_decls"][type_id])
                values = [self.operand(operand) for operand in operands]
                match type_name, values:
                    case ("core", "ops", "range", "RangeTo"), [end]:
                        return SliceRange(None, uint(end, "Usize"))
                    case ("core", "ops", "range", "RangeFrom"), [start]:
                        return SliceRange(uint(start, "Usize"), None)
                    case ("abc_shake256", "Reader"), [list(), list(), Scalar("Usize")]:
                        return Product(tuple(Cell(value) for value in values))
                    case _:
                        raise ValueError(f"Unsupported Rust sponge aggregate {type_name}")
            case _:
                return super().rvalue(node)

    def binary(self, operator, lhs, rhs):
        match operator, lhs, rhs:
            case "BitOr", Scalar("U8", int() as a), Scalar("U8", int() as b):
                return Scalar("U8", a | b)
            case {"Sub": "Panic"}, Scalar("Usize", int() as a), Scalar("Usize", int() as b):
                require(a >= b, "Rust sponge wrapper usize subtraction underflowed")
                return Scalar("Usize", a - b)
            case _:
                return super().binary(operator, lhs, rhs)

    def assign(self, dest, value):
        cell = self.place(dest)
        # A write through a chunk reference updates its elements in the enclosing array.
        if isinstance(cell.value, list) and isinstance(value, list) and "Projection" in dest["kind"]:
            require(len(cell.value) == len(value), "The Rust sponge output chunk width changed")
            for to, old in zip(cell.value, value):
                to.value = copy(old.value)
        else:
            cell.value = value

    def statements(self, statements):
        for node in statements:
            match node:
                case {"Assign": [dest, value]}:
                    self.assign(dest, self.rvalue(value))
                case _:
                    super().statements([node])

    def call(self, call):
        callee, widths = self.crate.callee(call)
        args = [self.operand(arg) for arg in call["args"]]
        value = Product(())
        match callee, widths, args:
            case ("core", "slice", "as_chunks"), [width], [Ref(Cell(PartitionedInput(blocks, tail)))]:
                require(width == RATE and self.chunks == 0, "Unexpected SHA3-256 input partition")
                self.chunks += 1
                value = Product((Cell(Ref(Cell(blocks))), Cell(Ref(Cell(tail)))))
            case ("core", "slice", "len"), [], [source]:
                value = Scalar("Usize", len(slice_cells(source)))
            case ("core", "array", "index_mut"), [width], [source, SliceRange(start, end)]:
                cells = slice_cells(source)
                start = 0 if start is None else start
                end = width if end is None else end
                require(len(cells) == width and 0 <= start <= end <= width, "Rust sponge range out of bounds")
                value = Ref(Cell(cells[start:end]))
            case ("core", "slice", "fill"), [], [target, item]:
                for cell in slice_cells(target):
                    cell.value = copy(item)
            case ("core", "slice", "copy_from_slice"), [], [target, source]:
                left, right = slice_cells(target), slice_cells(source)
                require(len(left) == len(right), "Rust sponge copy lengths differ")
                for cell, item in zip(left, right):
                    cell.value = copy(item.value)
            case ("abc_keccak_p1600", "absorb_rate_block"), [], [state, block]:
                lanes, bytes_ = slice_cells(state), slice_cells(block)
                require(len(lanes) == 25 and len(bytes_) == RATE, "Unexpected Rust sponge absorb dimensions")
                self.absorptions.append((reference(state), tuple(cell.value for cell in lanes),
                                         tuple(cell.value for cell in bytes_)))
                for i, cell in enumerate(lanes):
                    cell.value = LaneSymbol(len(self.absorptions), i)
            case ("core", "num", "to_le_bytes" | "to_be_bytes" as order), [], [LaneSymbol() as lane]:
                indices = range(8) if order == "to_le_bytes" else range(7, -1, -1)
                value = array(LaneByte(lane, index) for index in indices)
            case ("abc_shake256", "encode_block"), [], [argument]:
                nested = WrapperExecution(self.crate, {1: argument})
                nested.function(function_code(self.crate.declaration("fun_decls", "encode_block")))
                require(nested.locals[0].value == Product(()) and not nested.absorptions and not nested.encoding_calls,
                        "Unexpected SHAKE256 encode effects")
                self.encoding_calls.append(reference(argument))
            case _:
                return super().call(call)
        self.assign(call["dest"], value)


def bytes_for(kind, length):
    return array(Scalar("U8", f"{kind}:{i}") for i in range(length))


def check_sha3_loop(crate, loop):
    statements = code(loop)
    branch = next(i for i, node in enumerate(statements) if "Switch" in node)
    def calls(region):
        return [crate.callee(item["Call"]["call"])[0] for item in region if "Call" in item]

    prefix, iteration = statements[:branch], statements[branch + 1:-1]
    require(statements[-1] == {"Continue": 0} and
            calls(prefix) == [("core", "slice", "iter", "next")] and
            calls(iteration) == [("abc_keccak_p1600", "absorb_rate_block")], "Unexpected SHA3-256 input block loop")
    for node in (*prefix, *iteration):
        match node:
            case {"Call": {"call": {"dest": {"kind": {"Local": _}}}}}:
                pass
            case {"Assign": [{"kind": {"Local": _}}, rvalue]} if set(rvalue) <= {"Ref", "Use"}:
                pass
            case _:
                raise ValueError("Unexpected SHA3-256 input loop state or value transformation")


def check_wire(observed, absorbed, width):
    require(isinstance(observed, list) and len(observed) == width, "Unexpected sponge wire output width")
    offsets = []
    for i, cell in enumerate(observed):
        require(isinstance(cell.value, LaneByte) and cell.value.source == LaneSymbol(absorbed, i // 8),
                "The Rust sponge wire copied a different lane or permutation state")
        offsets.append(cell.value.offset)
    if offsets == [i % 8 for i in range(width)]:
        return "8 * (byte.val % 8)"
    if offsets == [7 - i % 8 for i in range(width)]:
        return "8 * (7 - byte.val % 8)"
    raise ValueError("Unsupported Rust sponge byte-order mapping")


def observe_sha3(crate, used, full):
    body = function_code(crate.declaration("fun_decls", "digest"))
    inputs = [bytes_for(f"block{index}", RATE) for index in range(full)]
    tail = bytes_for("tail", used)
    input_ = PartitionedInput(array(inputs), tail)
    model = WrapperExecution(crate, {1: Ref(Cell(input_))})
    loops = [statement["Loop"] for statement in body if "Loop" in statement]
    require(len(loops) == 2, "Expected SHA3-256's block and wire loops")
    check_sha3_loop(crate, loops[0])
    model.function(body)
    require(model.chunks == 1 and len(model.absorptions) == full + 1 and not model.encoding_calls,
            "Unexpected SHA3-256 partition or absorb count")
    state, initial, _ = model.absorptions[0]
    require(initial == (Scalar("U64", 0),) * 25, "SHA3-256 did not start at zero")
    for i, (destination, prior, block) in enumerate(model.absorptions):
        require(destination is state, "SHA3-256 changed the absorb state")
        if i > 0:
            require(prior == tuple(LaneSymbol(i, lane) for lane in range(25)), "SHA3-256 skipped the preceding state")
        if i < full:
            require(block == tuple(byte.value for byte in inputs[i]), "SHA3-256 reordered the full input blocks")
    return model.absorptions[-1][2], check_wire(model.locals[0].value, full + 1, 32)


def observe_shake(crate, used):
    body = function_code(crate.declaration("fun_decls", "finalize"))
    fields = (Cell(array(LaneSymbol(0, lane) for lane in range(25))),
              Cell(bytes_for("tail", RATE)), Cell(Scalar("Usize", used)))
    model = WrapperExecution(crate, {1: Product(fields)})
    model.function(body)
    require(model.chunks == 0 and len(model.absorptions) == len(model.encoding_calls) == 1,
            "SHAKE256 finalization did not absorb and encode once")
    state, prior, block = model.absorptions[0]
    require(state is fields[0] and prior == tuple(LaneSymbol(0, lane) for lane in range(25)),
            "SHAKE256 did not absorb into the prior state")
    returned = model.locals[0].value
    require(isinstance(returned, Product) and returned is model.encoding_calls[0].value and len(returned.fields) == 3,
            "SHAKE256 finalization returned a different reader")
    lanes, encoded, offset = (field.value for field in returned.fields)
    require(tuple(cell.value for cell in lanes) == tuple(LaneSymbol(1, lane) for lane in range(25)),
            "SHAKE256 reader did not return the absorbed lanes")
    return block, check_wire(encoded, 1, RATE), uint(offset, "Usize")


def inspect_padding(observer):
    first, *other = observer(0)
    suffix = uint(first[0], "U8")
    high = uint(first[-1], "U8")
    for used in range(RATE):
        block, *current = observer(used)
        tail = tuple(cell.value for cell in bytes_for("tail", used))
        last = high | (suffix if used == RATE - 1 else 0)
        prefix = tail + ((Scalar("U8", suffix),) if used < RATE - 1 else ())
        expected = prefix + (Scalar("U8", 0),) * (RATE - len(prefix) - 1) + (Scalar("U8", last),)
        require(block == expected and current == other, "Rust sponge padding or output changed with tail length")
    return suffix, high, *other


def lean_wrapper_module(sha3_ir, shake_ir, target):
    sha3 = WrapperCrate(sha3_ir, target, "abc_sha3_256", "digest")
    shake = WrapperCrate(shake_ir, target, "abc_shake256", "xof")

    def sha3_case(used):
        empty = observe_sha3(sha3, used, 0)
        require(empty == observe_sha3(sha3, used, 2), "Full blocks altered the SHA3-256 padding or wire")
        return empty

    sha3_suffix, sha3_high, digest_shift = inspect_padding(sha3_case)
    shake_suffix, shake_high, wire_shift, offset = inspect_padding(lambda used: observe_shake(shake, used))
    return f"""import KeccakSourceRefinement

namespace Abc.Refine.Keccak.WrapperSource

open Abc.Spec.KeccakRound
open Abc.Refine.Keccak.Source

def sourceSha3Padding (used : Nat) (tail : Block) : Block :=
  fun i => (if i.val < used then tail i else if i.val = used then {sha3_suffix} else 0) |||
    (if i.val = 135 then {sha3_high} else 0)

def sourceShakePadding (used : Nat) (tail : Block) : Block :=
  fun i => (if i.val < used then tail i else if i.val = used then {shake_suffix} else 0) |||
    (if i.val = 135 then {shake_high} else 0)

def sourceSha3Wire (state : State) (byte : Fin 32) : Byte :=
  (state (Fin.ofNat 25 (byte.val / 8))).extractLsb' ({digest_shift}) 8

def sourceShakeWire (state : State) (byte : Fin 136) : Byte :=
  (state (Fin.ofNat 25 (byte.val / 8))).extractLsb' ({wire_shift}) 8

def sourceSha3Digest (blocks : List Block) (used : Nat) (tail : Block) : Fin 32 → Byte :=
  sourceSha3Wire (sourceAbsorb (blocks.foldl sourceAbsorb (fun _ => 0)) (sourceSha3Padding used tail))

def sourceShakeFinalize (state : State) (used : Nat) (tail : Block) : State × Block × Nat :=
  let next := sourceAbsorb state (sourceShakePadding used tail)
  (next, sourceShakeWire next, {offset})

end Abc.Refine.Keccak.WrapperSource
"""
