"""Lower the active BlockMix passes with a symbolic outer index and lane size."""

from dataclasses import dataclass

from tools.verification.keccak.llbc import (
    Cell, Iteration, Product, Ref, Scalar, array, function_code, name, reference, require, split_chunks, uint,
)
from tools.verification.scrypt.salsa_llbc import SalsaExecution, lanes, output_words, word


@dataclass(frozen=True)
class Buffer:
    role: str
    offset: Scalar
    length: Scalar


@dataclass(frozen=True)
class Index:
    kind: str
    bound: Scalar


def size(number):
    return Scalar("Usize", number)


def coordinates(symbol, width):
    return array(Scalar("U8", f"({symbol} {index})") for index in range(width))


class BlockMixExecution(SalsaExecution):
    def __init__(self, crate):
        self.lane_length = size("laneLength")
        lane = Ref(Cell(Buffer("lane", size(0), self.lane_length)))
        temporary = Ref(Cell(Buffer("temporary", size(0), self.lane_length)))
        super().__init__(crate, {1: lane, 2: temporary}, [])
        self.seed = None
        self.width = None
        self.offset = None
        self.written = None
        self.output_chunks = None
        self.salsa_input = None

    def binary(self, operator, lhs, rhs):
        if lhs.kind == rhs.kind == "Usize" and isinstance(operator, dict):
            symbols = {"Add": "+", "Sub": "-", "Mul": "*", "Div": "/", "Rem": "%"}
            operation, semantics = next(iter(operator.items()))
            require(len(operator) == 1 and operation in symbols and semantics == "Panic",
                    "Unexpected BlockMix size operation")
            return size(f"({lhs.value} {symbols[operation]} {rhs.value})")
        return super().binary(operator, lhs, rhs)

    def rvalue(self, node):
        match node:
            case {"Aggregate": [{"Adt": [{"id": kind, "builtin": None}, None, None]}, [bound]]}:
                path = name(self.crate.data["type_decls"][kind])
                require(path[:-1] == ("core", "ops", "range") and path[-1] in ("RangeFrom", "RangeTo"),
                        "Expected a BlockMix slice range")
                limit = self.operand(bound)
                require(limit.kind == "Usize", "Expected a machine-size slice bound")
                return Index(path[-1], limit)
            case _:
                return super().rvalue(node)

    def range_index(self, source, index):
        span = reference(source).value
        require(isinstance(span, Buffer) and isinstance(index, Index), "Expected a BlockMix buffer and range")
        if index.kind == "RangeFrom":
            require(span.offset == size(0) and span.length == self.lane_length, "Unexpected BlockMix suffix")
            if span.role == "lane":
                require(self.seed is None and index.bound.value == "(laneLength - 64)",
                        "Expected the last 64 input bytes to seed BlockMix")
                self.seed = index.bound
                return Ref(Cell(coordinates("last", 64)))
            return Ref(Cell(Buffer(span.role, index.bound, self.binary({"Sub": "Panic"}, span.length, index.bound))))
        require(span.role == "temporary" and index.bound == size(64) and self.offset is None,
                "Expected one 64-byte output region per BlockMix iteration")
        self.offset = span.offset
        self.written = coordinates("old", 64)
        return Ref(Cell(self.written))

    def call(self, call):
        callee, widths = self.crate.callee(call)
        args = [self.operand(argument) for argument in call["args"]]
        match callee, widths, args:
            case ("core", "slice", "len"), [], [Ref() as source]:
                value = reference(source).value.length
            case ("core", "slice", "index", "index" | "index_mut"), [], [source, index]:
                value = self.range_index(source, index)
            case ("core", "slice", "chunks_exact"), [], [source, width]:
                require(reference(source).value == Buffer("lane", size(0), self.lane_length) and
                        width == size(64) and self.width is None, "Expected complete 64-byte input chunks in order")
                self.width = uint(width, "Usize")
                value = Iteration("block_chunks", iter([Ref(Cell(coordinates("block", self.width)))]))
            case ("core", "slice", "as_chunks_mut"), [width], [source] if reference(source).value is self.written:
                require(width == 4 and self.output_chunks is None, "Expected sixteen mutable four-byte output chunks")
                value = split_chunks(source, width)
                self.output_chunks = reference(value.fields[0].value).value
            case ("core", "iter", "traits", "iterator", "Iterator", "enumerate"), [], [Iteration("block_chunks", items)]:
                value = Iteration("enumerate", (Product((Cell(size("index")), Cell(item))) for item in items))
            case ("core", "num", "from_le_bytes" | "from_be_bytes" as conversion), [], [list() as items]:
                require(len(items) == 4 and all(cell.value.kind == "U8" for cell in items), "Expected four BlockMix bytes")
                aa, bb, cc, dd = [cell.value.lean() for cell in items]
                value = Scalar("U32", f"((({dd} ++ {cc}) ++ {bb}) ++ {aa})" if conversion == "from_le_bytes" else
                               f"((({aa} ++ {bb}) ++ {cc}) ++ {dd})")
            case ("core", "num", "to_le_bytes" | "to_be_bytes" as conversion), [], [item]:
                indices = range(4) if conversion == "to_le_bytes" else reversed(range(4))
                value = array(Scalar("U8", f"({word(item)}).extractLsb' {8 * index} 8") for index in indices)
            case ("abc_scrypt", "salsa8"), [], [Ref() as state]:
                require(self.salsa_input is None, "Expected one Salsa20/8 call per BlockMix iteration")
                words = reference(state).value
                require(len(words) == 16, "Expected sixteen BlockMix words")
                self.salsa_input = array(cell.value for cell in words)
                for cell, output in zip(words, lanes("salsa"), strict=True):
                    cell.value = output.value
                value = Product(())
            case _:
                return super().call(call)
        self.place(call["dest"]).value = value


def lean_body(crate):
    source = BlockMixExecution(crate)
    body = function_code(crate.declaration("fun_decls", "block_mix"))
    loops = [index for index, statement in enumerate(body) if "Loop" in statement]
    require(len(loops) == 2, "Expected the BlockMix seed and outer traversal loops")
    source.statements(body[:loops[1]])
    accumulators = [cell.value for cell in source.locals.values() if isinstance(cell.value, list) and
                    len(cell.value) == 16 and all(isinstance(item.value, Scalar) and item.value.kind == "U32"
                                                  for item in cell.value)]
    require(len(accumulators) == 1 and not source.bindings and source.seed is not None and source.width == 64,
            "Unexpected BlockMix initial accumulator or iterator")
    words = accumulators[0]
    initial = array(cell.value for cell in words)

    def iteration(_location, _value, operations):
        for cell, old in zip(words, lanes("previous"), strict=True):
            cell.value = old.value
        source.statements(operations)

    source.run_loop(body[loops[1]]["Loop"], iteration)
    source.function(body[loops[1] + 1:])
    require(source.salsa_input is not None and source.offset is not None and source.output_chunks is not None,
            "Expected one Salsa20/8 output in BlockMix")
    serialized = [byte for chunk in source.output_chunks for byte in chunk.value]
    require(all(cell.value != old.value for cell, old in zip(serialized, coordinates("old", 64), strict=True)),
            "Expected BlockMix to write the entire Salsa20/8 output")
    return "\n".join([
        "", "namespace Abc.Refine.Scrypt.Source", "",
        "def sourceBlockMixSeedOffset (laneLength : Nat) : Nat :=", f"  {source.seed.value}", "",
        "def sourceBlockMixCount (laneLength : Nat) : Nat :=", f"  laneLength / {source.width}", "",
        "def sourceBlockMixOffset (laneLength index : Nat) : Nat :=", f"  {source.offset.value}", "",
        "def sourceBlockMixSeed (last : Fin 64 → BitVec 8) (index : Fin 16) : BitVec 32 :=",
        *output_words(Cell(initial)), "",
        "def sourceBlockMixInput (previous : Fin 16 → BitVec 32) (block : Fin 64 → BitVec 8)",
        "    (index : Fin 16) : BitVec 32 :=",
        *source.bindings, *output_words(Cell(source.salsa_input)), "",
        "def sourceBlockMixSerialize (salsa : Fin 16 → BitVec 32) (index : Fin 64) : BitVec 8 :=",
        "  match index.val with", *(f"  | {i} => {cell.value.lean()}" for i, cell in enumerate(serialized)),
        "  | _ => 0", "", "end Abc.Refine.Scrypt.Source", "",
    ])
