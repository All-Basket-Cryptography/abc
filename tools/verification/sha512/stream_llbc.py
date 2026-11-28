"""Interpret the SHA-512 length gate and final padding from structured LLBC."""

from dataclasses import dataclass

from llbc import constant_values, ident, local, require


def operations(block):
    return [row["kind"] for row in block["statements"]
            if not set(row["kind"]) & {"StorageLive", "StorageDead", "Borrowck"}]


def body(declaration):
    return declaration["body"]["Structured"]["body"]


def scalar_types(tree, table):
    if isinstance(tree, dict):
        match tree:
            case {"Value": [index, {"Scalar": {"Integer": {"Unsigned": kind}}}]}:
                table[index] = kind
        for item in tree.values():
            scalar_types(item, table)
    elif isinstance(tree, list):
        for item in tree:
            scalar_types(item, table)


@dataclass(frozen=True)
class Scalar:
    kind: str
    lean: str
    number: int | None = None

    @staticmethod
    def constant(kind, number):
        return Scalar(kind, str(number), number)


@dataclass(frozen=True)
class Ref:
    value: object


@dataclass(frozen=True)
class IndexedBlock:
    index: Scalar
    tail: bool


class Terms:
    def __init__(self, translated):
        self.crate = translated
        self.constants = {}
        constant_values(translated, self.constants)
        self.types = {}
        scalar_types(translated, self.types)
        self.globals = {}

    def declaration(self, collection, name):
        matches = [decl for decl in self.crate[collection] if decl and ident(decl) == name]
        require(len(matches) == 1, f"Expected one LLBC declaration {name}")
        return matches[0]

    def raw_constant(self, tagged):
        match tagged:
            case {"Value": [_, [payload, _]]}:
                return payload
            case {"Deduplicated": index}:
                return self.constants[index]
            case _:
                raise ValueError("Unexpected LLBC constant encoding")

    def constant(self, tagged):
        match self.raw_constant(tagged):
            case {"Integer": {"Unsigned": [kind, integer]}}:
                return Scalar.constant(kind, int(integer))
            case {"Bool": value}:
                return value
            case _:
                raise ValueError("Expected an unsigned scalar or bool constant")

    def global_value(self, index):
        if index not in self.globals:
            declaration = self.crate["global_decls"][index]
            if ident(declaration) == ("core", "num", "MAX"):
                match declaration["ty"]:
                    case {"Deduplicated": scalar} if self.types[scalar] == "U128":
                        return Scalar("U128", "(2 ^ 128 - 1)")
                    case _:
                        raise ValueError("Expected the Rust u128 maximum")
            match self.raw_constant(declaration["value"]):
                case {"Call": [{"kind": {"Fun": initializer}}, []]}:
                    code = operations(body(self.crate["fun_decls"][initializer]))
                    interpreter = Interpret(self, {})
                    require(code[-1] == "Return", "Expected a returning constant initializer")
                    interpreter.statements(code[:-1])
                    require(not interpreter.effects, "A constant initializer has an effect")
                    self.globals[index] = interpreter.values[0]
                case _:
                    self.globals[index] = self.constant(declaration["value"])
        return self.globals[index]

    def function_name(self, call):
        match call["func"]:
            case {"Regular": {"kind": {"Fun": index}}}:
                return ident(self.crate["fun_decls"][index])
            case _:
                raise ValueError("Unsupported indirect LLBC call")


class Interpret:
    """Lower the supported scalar terms and record every modeled write or call effect."""

    def __init__(self, terms, values):
        self.terms = terms
        self.values = values.copy()
        self.effects = []

    def place(self, node):
        match node["kind"]:
            case {"Local": index}:
                return self.values[index]
            case {"Global": {"id": index}}:
                return self.terms.global_value(index)
            case {"Projection": [inner, "Deref"]}:
                value = self.place(inner)
                require(isinstance(value, Ref), "Expected an LLBC reference")
                return value.value
            case {"Projection": [inner, {"Field": [None, index]}]}:
                require(self.place(inner) == "context", "Expected a Sha512 context field")
                return ("state", "block", Scalar("Usize", "buffered"), Scalar("U128", "prior"))[index]
            case _:
                raise ValueError(f"Unsupported streaming LLBC place {node['kind']}")

    def operand(self, node):
        match node:
            case {"Copy": value} | {"Move": value}:
                return self.place(value)
            case {"Const": value}:
                return self.terms.constant(value)
            case _:
                raise ValueError("Unsupported streaming LLBC operand")

    def assign(self, place, value):
        match place["kind"]:
            case {"Local": index}:
                self.values[index] = value
            case _:
                target = self.place(place)
                match target, value:
                    case Scalar("U128", "prior", None), Scalar("U128"):
                        self.effects.append(("counter", value))
                    case IndexedBlock(index, False), Scalar("U8"):
                        self.effects.append(("store", index, value))
                    case _:
                        raise ValueError("Unsupported streaming LLBC write")

    def aggregate(self, descriptor, values):
        type_, variant, _ = descriptor["Adt"]
        name = ident(self.terms.crate["type_decls"][type_["id"]])
        match name, variant, values:
            case ("core", "ops", "range", "RangeFrom"), None, [Scalar("Usize") as start]:
                return IndexedBlock(start, True)
            case ("abc_sha512", "MessageTooLong"), None, []:
                return "MessageTooLong"
            case ("core", "result", "Result"), 1, ["MessageTooLong"]:
                return "Err(MessageTooLong)"
            case _:
                raise ValueError(f"Unsupported streaming aggregate {name}::{variant}")

    def binary(self, operation, lhs, rhs):
        require(isinstance(lhs, Scalar) and isinstance(rhs, Scalar) and lhs.kind == rhs.kind,
                "Unexpected streaming arithmetic scalar types")
        match operation:
            case "Gt" | "Ge":
                operator = ">" if operation == "Gt" else "≥"
                return Scalar("Prop", f"({lhs.lean} {operator} {rhs.lean})")
            case {"Add": "Panic"}:
                operator = "+"
            case {"Sub": "Panic"}:
                operator = "-"
            case {"Mul": "Panic"}:
                operator = "*"
            case {"Div": "Panic"}:
                operator = "/"
            case _:
                raise ValueError(f"Unexpected streaming LLBC operator {operation}")
        return Scalar(lhs.kind, f"({lhs.lean} {operator} {rhs.lean})")

    def rvalue(self, node):
        match node:
            case {"Use": [operand, "Yes"]}:
                return self.operand(operand)
            case {"Ref": {"place": value, "kind": kind}} if kind in ("Shared", "Mut", "TwoPhaseMut"):
                return Ref(self.place(value))
            case {"UnaryOp": [{"Cast": {"Scalar": [
                    {"Integer": {"Unsigned": "Usize"}}, {"Integer": {"Unsigned": "U128"}}]}}, operand]}:
                value = self.operand(operand)
                require(isinstance(value, Scalar) and value.kind == "Usize", "Expected a slice length cast")
                return Scalar("U128", f"({value.lean} % 2 ^ 128)")
            case {"BinaryOp": [operator, lhs, rhs]}:
                return self.binary(operator, self.operand(lhs), self.operand(rhs))
            case {"Aggregate": [descriptor, values]}:
                return self.aggregate(descriptor, [self.operand(value) for value in values])
            case _:
                raise ValueError(f"Unsupported streaming LLBC value {node}")

    def call(self, call):
        name = self.terms.function_name(call)
        args = [self.operand(arg) for arg in call["args"]]
        value = None
        match name, args:
            case ("core", "slice", "len"), [Ref("input")]:
                value = Scalar("Usize", "incoming")
            case ("core", "array", "index_mut"), [Ref("block"), Scalar("Usize") as index]:
                value = Ref(IndexedBlock(index, False))
            case ("core", "array", "index_mut"), [Ref("block"), IndexedBlock(_, True) as tail]:
                value = Ref(tail)
            case ("core", "array", "as_mut_slice"), [Ref("block")]:
                value = Ref("block")
            case ("core", "num", "to_be_bytes"), [Scalar("U128") as length]:
                value = ("be128", length)
            case ("core", "array", "as_slice"), [Ref(("be128", Scalar("U128") as length))]:
                value = Ref(("be128", length))
            case ("core", "slice", "fill"), [Ref(IndexedBlock(start, True)), Scalar("U8") as byte]:
                self.effects.append(("fill_tail", start, byte))
            case ("core", "slice", "fill"), [Ref("block"), Scalar("U8") as byte]:
                self.effects.append(("reset", byte))
            case ("abc_sha512", "compress"), [Ref("state"), Ref("block")]:
                self.effects.append(("compress",))
            case ("core", "slice", "copy_from_slice"), [Ref(IndexedBlock(start, True)), Ref(("be128", length))]:
                self.effects.append(("write_length", start, length))
            case _:
                raise ValueError(f"Unsupported streaming LLBC call {name} with inputs {args}")
        self.assign(call["dest"], value)

    def statements(self, code):
        for node in code:
            match node:
                case {"Assign": [dest, value]}:
                    self.assign(dest, self.rvalue(value))
                case {"Call": {"call": call}}:
                    self.call(call)
                case _:
                    raise ValueError(f"Unsupported streaming LLBC operation {node}")

    def split(self, switch):
        data = switch["data"]
        condition = self.operand(data["scrutinee"]["Value"])
        branches = data["branches"]
        require(isinstance(condition, Scalar) and condition.kind == "Prop" and len(branches) == 1 and
                self.terms.constant(branches[0][0]) is False and len(switch["branches"]) == 2 and
                sorted([branches[0][1], data["fallback"]]) == [0, 1], "Unexpected boolean LLBC branch")
        return condition, operations(switch["branches"][data["fallback"]]), operations(switch["branches"][branches[0][1]])


def scalar_code(terms, name, first=None):
    declaration = terms.declaration("global_decls", ("abc_sha512", name))
    value = terms.global_value(declaration["def_id"])
    require(isinstance(value, Scalar) and (first is None or value.kind == first), f"Invalid scalar global {name}")
    return value


def length_gate(terms):
    update = terms.declaration("fun_decls", ("abc_sha512", "update"))
    model = Interpret(terms, {1: Ref("context"), 2: Ref("input")})
    match operations(body(update)):
        case [*guard, {"Switch": switch}, "Return"]:
            model.statements(guard)
        case _:
            raise ValueError("Expected the update length branch to cover the full update body")
    require(not model.effects, "Update length evaluation has a write or call effect")
    reject, yes, no = model.split(switch)
    failure = Interpret(terms, model.values)
    failure.statements(yes)
    require(not failure.effects and failure.values[0] == "Err(MessageTooLong)",
            "The rejecting update branch must return MessageTooLong without a write")
    success = Interpret(terms, model.values)
    for node in no:
        success.statements([node])
        if success.effects:
            match success.effects:
                case [("counter", value)]:
                    return reject, value
                case _:
                    break
    raise ValueError("The admitted update branch must write its counter before other effects")


def final_padding(terms):
    finalizer = terms.declaration("fun_decls", ("abc_sha512", "finalize"))
    code = operations(body(finalizer))
    branch = next(index for index, node in enumerate(code) if "Switch" in node)
    model = Interpret(terms, {1: "context"})
    model.statements(code[:branch])
    condition, yes, no = model.split(code[branch]["Switch"])
    extra, single = Interpret(terms, model.values), Interpret(terms, model.values)
    extra.statements(yes)
    single.statements(no)
    require(not single.effects, "Unexpected single-block branch effect before the length write")
    match extra.effects:
        case [("compress",), ("reset", reset)]:
            pass
        case _:
            raise ValueError("Expected the two-block branch to compress before zeroing the block")
    for node in code[branch + 1:]:
        model.statements([node])
        if model.effects[-1:] == [("compress",)]:
            break
    match model.effects:
        case [("store", marker_at, marker), ("fill_tail", zero_at, zero),
              ("write_length", length_at, bit_length), ("compress",)]:
            return marker_at, marker, zero_at, zero, condition, reset, length_at, bit_length
        case _:
            raise ValueError("Unexpected streaming padding order")


def lean_stream_module(artifact, target):
    require(artifact["has_errors"] is False, "Charon reported errors in the SHA-512 digest closure")
    crate = artifact["translated"]
    require(crate["crate_name"] == "abc_sha512" and crate["options"]["start_from"] == ["crate::digest"] and
            len(crate["target_information"]) == 1 and
            crate["target_information"][0]["key"] == target and
            crate["target_information"][0]["value"]["target_pointer_size"] == 8,
            "Expected the source-linked 64-bit SHA-512 digest closure")
    terms = Terms(crate)
    context = terms.declaration("type_decls", ("abc_sha512", "Sha512"))
    fields = context["kind"]["Struct"]
    require([field["name"] for field in fields] == ["state", "block", "buffered", "bytes"],
            "The SHA-512 context layout changed")
    width = terms.constant(fields[1]["ty"]["Value"][1]["Array"][1])
    require(isinstance(width, Scalar) and width.kind == "Usize", "Expected a fixed SHA-512 byte buffer")
    capacity = scalar_code(terms, "BLOCK_BYTES", "Usize")
    require(width.number == capacity.number, "SHA-512 block capacity differs from the buffer width")
    reject, count = length_gate(terms)
    marker_at, marker, zero_at, zero, extra, reset, length_at, bit_length = final_padding(terms)
    return f"""import Sha512Streaming

namespace Abc.Refine.Sha512.StreamSource

open Abc.Spec.Sha512 (Byte)

def sourceRejects (prior incoming : Nat) : Prop := {reject.lean}
instance (prior incoming : Nat) : Decidable (sourceRejects prior incoming) :=
  inferInstanceAs (Decidable {reject.lean})
def sourceCount (prior incoming : Nat) : Nat := {count.lean}

def sourceCapacity : Nat := {capacity.lean}
def sourceMarkerAt (buffered : Nat) : Nat := {marker_at.lean}
def sourceMarker : Byte := {marker.lean}
def sourceZeroAt (buffered : Nat) : Nat := {zero_at.lean}
def sourceZero : Byte := {zero.lean}
def sourceExtraBlock (buffered : Nat) : Prop := {extra.lean}
instance (buffered : Nat) : Decidable (sourceExtraBlock buffered) :=
  inferInstanceAs (Decidable {extra.lean})
def sourceReset : Byte := {reset.lean}
def sourceLengthAt : Nat := {length_at.lean}
def sourceBitLength (prior : Nat) : Nat := {bit_length.lean}

end Abc.Refine.Sha512.StreamSource
"""
