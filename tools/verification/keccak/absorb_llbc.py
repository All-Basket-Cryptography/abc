"""Lower SHAKE256's constructor, incremental absorption, and public xof link."""

from llbc import Cell, Execution, Option, Product, Ref, Scalar, array, code, function_code, name, reference, require
from reader_llbc import ReadExecution, choose, number
from wrapper_llbc import WrapperCrate, WrapperExecution, check_sha3_loop


class AbsorbExecution(ReadExecution):
    def __init__(self, crate):
        Execution.__init__(self, crate, {
            1: Ref(Cell(Product((Cell("state"), Cell("storage"), Cell(number("buffered")))))),
            2: Ref(Cell("input")),
        })
        self.effects = []

    def binary(self, operator, lhs, rhs):
        if operator == "Lt":
            return Scalar("Prop", f"({choose(lhs)} < {choose(rhs)})")
        return super().binary(operator, lhs, rhs)

    def rvalue(self, node):
        match node:
            case {"Aggregate": [{"Adt": [{"id": type_id}, None, None]}, [end]]}:
                value = choose(self.operand(end))
                match name(self.crate.data["type_decls"][type_id]):
                    case ("core", "ops", "range", "RangeTo"):
                        return ("range", "0", value)
                    case ("core", "ops", "range", "RangeFrom"):
                        return ("from", value)
                    case _:
                        raise ValueError("Unexpected SHAKE256 update range")
            case _:
                return super().rvalue(node)

    def call(self, call):
        callee, widths = self.crate.callee(call)
        inputs = [self.operand(arg) for arg in call["args"]]
        value = Product(())
        match callee, widths, inputs:
            case ("core", "slice", "len"), [], [Ref(Cell("input"))]:
                value = number("incoming")
            case ("core", "slice", "len"), [], [Ref(Cell(("tail", _)))]:
                value = number("tail.length")
            case ("core", "array", "index_mut"), [136], [Ref(Cell("storage")), ("range", start, end)]:
                value = Ref(Cell(("destination", start, end)))
            case ("core", "slice", "index", "index"), [], [Ref(Cell("input")), ("range", "0", end)]:
                value = Ref(Cell(("prefix", end)))
            case ("core", "slice", "index", "index"), [], [Ref(Cell("input")), ("from", start)]:
                value = Ref(Cell(("remaining", start)))
            case ("core", "slice", "copy_from_slice"), [], [Ref(Cell(("destination", start, end))), Ref(Cell(source))]:
                self.effects.append(("copy", start, end, source))
            case ("abc_keccak_p1600", "absorb_rate_block"), [], [Ref(Cell("state")), Ref(Cell(block))]:
                self.effects.append(("absorb", block))
            case ("core", "slice", "as_chunks"), [136], [Ref(Cell(source))]:
                value = Product((Cell(Ref(Cell(("blocks", source)))), Cell(Ref(Cell(("tail", source))))))
            case ("core", "slice", "iter", "into_iter"), [], [Ref(Cell(("blocks", _) as pair))]:
                value = pair
            case ("core", "slice", "iter", "next"), [], [Ref(Cell(("blocks", source)))]:
                self.effects.append(("next", source))
                value = Option(Cell(Ref(Cell(("chunk", source)))))
            case ("core", "cmp", "Ord", "min" | "max" as op), [], [lhs, rhs]:
                value = number(f"({op} {choose(lhs)} {choose(rhs)})")
            case _:
                raise ValueError(f"Unsupported SHAKE256 update call {callee} {widths}")
        self.place(call["dest"]).value = value

    def buffered(self):
        return choose(reference(self.locals[1].value).value.fields[2].value)

    def run_loop(self, loop):
        check_sha3_loop(self.crate, loop)
        statements = code(loop)
        branch = next(i for i, node in enumerate(statements) if "Switch" in node)
        self.statements(statements[:branch])
        _, option = self.option_switch(statements[branch]["Switch"])
        require(option.item is not None, "Expected a symbolic complete SHAKE256 block")
        self.statements(statements[branch + 1:-1])


def continuation(model, statements, source):
    model.effects.clear()
    model.function(statements)
    require(model.effects == [("next", source), ("absorb", ("chunk", source)),
                            ("copy", "0", "tail.length", ("tail", source))] and
            model.buffered() == "tail.length" and model.locals[0].value == Product(()),
            "Unexpected SHAKE256 full-block or tail driver effects")


def observe_update(crate):
    statements = function_code(crate.declaration("fun_decls", "update"))
    branch = next(i for i, node in enumerate(statements) if "Switch" in node)
    direct = AbsorbExecution(crate)
    direct.statements(statements[:branch])
    has_pending, yes, no = direct.branch(statements[branch]["Switch"])
    require(not direct.effects and not no and direct.buffered() == "buffered",
            "SHAKE256 update mutates before deciding whether to complete a prefix")
    continuation(direct, statements[branch + 1:], "input")

    prefix = AbsorbExecution(crate)
    prefix.statements(statements[:branch])
    split = next(i for i, node in enumerate(yes) if "Switch" in node)
    prefix.statements(yes[:split])
    match prefix.effects:
        case [("copy", "buffered", end, ("prefix", copied))] if prefix.buffered() == end:
            pass
        case _:
            raise ValueError("Unexpected SHAKE256 prefix-copy window")
    stop, early, full = prefix.branch(yes[split]["Switch"])
    require(split == len(yes) - 1, "Unexpected SHAKE256 work after the prefix completion branch")
    prefix.effects.clear()
    prefix.function(early)
    require(not prefix.effects and prefix.buffered() == end and prefix.locals[0].value == Product(()),
            "Unexpected SHAKE256 incomplete-prefix exit")
    prefix.statements(full)
    remaining = ("remaining", copied)
    require(prefix.effects == [("absorb", "storage")] and reference(prefix.locals[2].value).value == remaining,
            "SHAKE256 did not absorb the completed prefix before continuing")
    continuation(prefix, statements[branch + 1:], remaining)
    return has_pending, copied, end, stop


class ApiExecution(WrapperExecution):
    def __init__(self, crate, arguments):
        super().__init__(crate, arguments)
        self.context = object()
        self.reader = object()
        self.api_calls = []

    def rvalue(self, node):
        match node:
            case {"Aggregate": [{"Adt": [{"id": index}, None, None]}, operands]} if operands:
                if name(self.crate.data["type_decls"][index]) == ("abc_shake256", "Shake256"):
                    return Product(tuple(Cell(self.operand(op)) for op in operands))
        return super().rvalue(node)

    def call(self, call):
        callee, widths = self.crate.callee(call)
        args = [self.operand(operand) for operand in call["args"]]
        match callee, widths, args:
            case ("abc_shake256", "new"), [], []:
                self.api_calls.append("new")
                value = self.context
            case ("abc_shake256", "update"), [], [context, Ref(Cell("input"))] if reference(context).value is self.context:
                self.api_calls.append("update")
                value = Product(())
            case ("abc_shake256", "finalize"), [], [context] if context is self.context:
                self.api_calls.append("finalize")
                value = self.reader
            case ("abc_shake256", "read"), [], [reader, Ref(Cell("output"))] if reference(reader).value is self.reader:
                self.api_calls.append("read")
                value = Product(())
            case _:
                return super().call(call)
        self.assign(call["dest"], value)


def initial_state(crate):
    model = ApiExecution(crate, {})
    model.function(function_code(crate.declaration("fun_decls", "new")))
    result = model.locals[0].value
    require(isinstance(result, Product) and len(result.fields) == 3 and not model.api_calls and not model.absorptions,
            "Unexpected SHAKE256 constructor effects")
    lanes, storage, buffered = (cell.value for cell in result.fields)
    require(isinstance(lanes, list) and len(lanes) == 25 and all(cell.value == lanes[0].value for cell in lanes)
            and isinstance(storage, list) and len(storage) == 136 and all(cell.value == storage[0].value for cell in storage),
            "Unexpected SHAKE256 constructor buffer layout")
    require(isinstance(lanes[0].value, Scalar) and lanes[0].value.kind == "U64" and
            isinstance(storage[0].value, Scalar) and storage[0].value.kind == "U8",
            "Unexpected SHAKE256 constructor element types")
    return lanes[0].value.value, storage[0].value.value, choose(buffered)


def check_xof(crate):
    model = ApiExecution(crate, {1: Ref(Cell("input")), 2: Ref(Cell("output"))})
    model.function(function_code(crate.declaration("fun_decls", "xof")))
    require(model.api_calls == ["new", "update", "finalize", "read"] and model.locals[0].value == Product(())
            and not model.absorptions and not model.encoding_calls,
            "SHAKE256 xof did not compose new, update, finalize and read on the original input/output")


def lean_absorb_module(artifact, target):
    crate = WrapperCrate(artifact, target, "abc_shake256", "xof")
    lane, byte, buffered = initial_state(crate)
    active, copied, end, done = observe_update(crate)
    check_xof(crate)
    return f"""import KeccakReaderSourceRefinement

namespace Abc.Refine.Keccak.AbsorbSource

open Abc.Spec.KeccakRound

def sourceNewLanes : State := fun _ => {lane}
def sourceNewStorage : List Byte := List.replicate 136 {byte}
def sourceNewBuffered : Nat := {buffered}
def sourceHasPending (buffered : Nat) : Prop := {active}
instance (buffered : Nat) : Decidable (sourceHasPending buffered) :=
  inferInstanceAs (Decidable {active})
def sourceCopied (incoming buffered : Nat) : Nat := {copied}
def sourceEnd (incoming buffered : Nat) : Nat := {end}
def sourceStops (incoming buffered : Nat) : Prop := {done}
instance (incoming buffered : Nat) : Decidable (sourceStops incoming buffered) :=
  inferInstanceAs (Decidable {done})

end Abc.Refine.Keccak.AbsorbSource
"""
