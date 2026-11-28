"""Lower one symbolic SHAKE256 read-loop transition."""

from llbc import Cell, Execution, Product, Ref, Scalar, code, function_code, name, reference, require
from wrapper_llbc import WrapperCrate


def number(text):
    return Scalar("Usize", text)


def choose(value):
    require(isinstance(value, Scalar) and value.kind == "Usize", "Expected a SHAKE256 cursor expression")
    return str(value.value)


class ReadExecution(Execution):
    def __init__(self, crate, remaining="remaining", cursor="offset"):
        self.reader = Cell(Product((Cell("lanes"), Cell("block"), Cell(number(cursor)))))
        super().__init__(crate, {1: Ref(self.reader), 2: Ref(Cell("output"))})
        self.effects = []
        self.remaining = remaining

    def binary(self, operator, lhs, rhs):
        match operator:
            case "Eq":
                return Scalar("Prop", f"({choose(lhs)} = {choose(rhs)})")
            case "Ne":
                return Scalar("Prop", f"({choose(lhs)} ≠ {choose(rhs)})")
            case {"Add": "Panic"} | {"Sub": "Panic"}:
                symbol = "+" if "Add" in operator else "-"
                return number(f"({choose(lhs)} {symbol} {choose(rhs)})")
            case _:
                return super().binary(operator, lhs, rhs)

    def rvalue(self, node):
        match node:
            case {"Aggregate": [{"Adt": [{"id": type_id}, None, None]}, [start, end]]}:
                require(name(self.crate.data["type_decls"][type_id]) == ("core", "ops", "range", "Range"),
                        "Expected SHAKE256's output byte range")
                return ("range", choose(self.operand(start)), choose(self.operand(end)))
            case _:
                return super().rvalue(node)

    def call(self, call):
        callee, widths = self.crate.callee(call)
        inputs = [self.operand(arg) for arg in call["args"]]
        value = Product(())
        match callee, widths, inputs:
            case ("core", "slice", "is_empty"), [], [Ref(Cell("output"))]:
                value = Scalar("Prop", f"({self.remaining} = 0)")
            case ("core", "slice", "len"), [], [Ref(Cell("output"))]:
                value = number(self.remaining)
            case ("core", "cmp", "Ord", "min" | "max" as op), [], [lhs, rhs]:
                value = number(f"({op} {choose(lhs)} {choose(rhs)})")
            case ("abc_keccak_p1600", "keccak_p1600"), [], [Ref(Cell("lanes"))]:
                self.effects.append(("permute",))
            case ("abc_shake256", "encode_block"), [], [argument] if reference(argument) is self.reader:
                self.effects.append(("encode",))
            case ("core", "slice", "split_at_mut"), [], [Ref(Cell("output")), length]:
                value = Product((Cell(Ref(Cell(("destination", choose(length))))),
                                 Cell(Ref(Cell(("remainder", choose(length)))))))
            case ("core", "array", "index"), [136], [Ref(Cell("block")), ("range", start, end)]:
                value = Ref(Cell(("source", start, end)))
            case ("core", "slice", "copy_from_slice"), [], [Ref(Cell(("destination", length))),
                                                           Ref(Cell(("source", start, end)))]:
                self.effects.append(("copy", length, start, end))
            case _:
                raise ValueError(f"Unsupported SHAKE256 reader call {callee} {widths}")
        self.place(call["dest"]).value = value

    def branch(self, switch):
        data = switch["data"]
        condition = self.operand(data["scrutinee"]["Value"])
        tags = data["branches"]
        require(isinstance(condition, Scalar) and condition.kind == "Prop" and len(tags) == 1 and
                self.crate.raw(tags[0][0]) == {"Bool": False} and len(switch["branches"]) == 2 and
                sorted((tags[0][1], data["fallback"])) == [0, 1], "Unexpected SHAKE256 reader branch")
        return condition.value, code(switch["branches"][data["fallback"]]), code(switch["branches"][tags[0][1]])

    def offset(self):
        return choose(self.reader.value.fields[2].value)


def reader_terms(artifact, target):
    crate = WrapperCrate(artifact, target, "abc_shake256", "xof")
    body = function_code(crate.declaration("fun_decls", "read"))
    [loop] = [i for i, node in enumerate(body) if "Loop" in node]
    model = ReadExecution(crate)
    model.function(body[:loop] + body[loop + 1:])
    require(not model.effects and model.locals[0].value == Product(()) and model.offset() == "offset" and
            reference(model.locals[2].value).value == "output", "SHAKE256 work outside the read loop changed")
    statements = code(body[loop]["Loop"])
    empty_at, refresh_at = [i for i, node in enumerate(statements) if "Switch" in node]
    model.statements(statements[:empty_at])
    empty, stop, continuing = model.branch(statements[empty_at]["Switch"])
    require(stop == [{"Break": 0}] and not continuing and not model.effects, "SHAKE256 empty read branch changed")
    model.statements(statements[empty_at + 1:refresh_at])
    refresh, yes, no = model.branch(statements[refresh_at]["Switch"])
    require(not no and not model.effects and model.offset() == "offset", "SHAKE256 unexpectedly mutates before refresh")
    model.statements(yes)
    require(model.effects == [("permute",), ("encode",)], "SHAKE256 refresh must permute before encoding")
    reset = model.offset()
    model = ReadExecution(crate, cursor="readyOffset")
    require(statements[-1] == {"Continue": 0}, "SHAKE256 reader does not continue after copying")
    model.statements(statements[refresh_at + 1:-1])
    match model.effects:
        case [("copy", count, start, end)]:
            require(reference(model.locals[2].value).value == ("remainder", count),
                    "SHAKE256 copy does not continue with the uncopied output")
            return empty, refresh, reset, count, start, end, model.offset()
        case _:
            raise ValueError("Unexpected SHAKE256 read-loop effects")


def lean_reader_module(artifact, target):
    empty, refresh, reset, count, start, end, offset = reader_terms(artifact, target)
    start_parameter = "remaining" if "remaining" in start else "_remaining"
    return f"""import KeccakWrapperSourceRefinement
import KeccakSpongeRead

namespace Abc.Refine.Keccak.ReaderSource

def sourceReadEmpty (remaining : Nat) : Prop := {empty}
instance (remaining : Nat) : Decidable (sourceReadEmpty remaining) :=
  inferInstanceAs (Decidable {empty})
def sourceReadRefresh (offset : Nat) : Prop := {refresh}
instance (offset : Nat) : Decidable (sourceReadRefresh offset) :=
  inferInstanceAs (Decidable {refresh})
def sourceReadReset : Nat := {reset}
def sourceReadCount (remaining readyOffset : Nat) : Nat := {count}
def sourceReadStart ({start_parameter} readyOffset : Nat) : Nat := {start}
def sourceReadEnd (remaining readyOffset : Nat) : Nat := {end}
def sourceReadNext (remaining readyOffset : Nat) : Nat := {offset}

end Abc.Refine.Keccak.ReaderSource
"""
