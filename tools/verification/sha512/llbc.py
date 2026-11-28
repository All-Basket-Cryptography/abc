"""Lower the normal-path assignments of the four SHA-512 compression loop bodies."""

from dataclasses import dataclass


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def ident(declaration):
    return tuple(part["Ident"][0] for part in declaration["item_meta"]["name"] if "Ident" in part)


def local(place):
    match place["kind"]:
        case {"Local": index}:
            return index
        case _:
            raise ValueError("Expected an LLBC local destination")


def constant_values(tree, table):
    if isinstance(tree, dict):
        match tree:
            case {"Value": [identifier, [value, _]]}:
                previous = table.setdefault(identifier, value)
                require(previous == value, "Conflicting LLBC constant definitions")
        for value in tree.values():
            constant_values(value, table)
    elif isinstance(tree, list):
        for item in tree:
            constant_values(item, table)


@dataclass(frozen=True)
class Word:
    lean: str


@dataclass(frozen=True)
class Integer:
    type: str
    value: int


@dataclass(frozen=True)
class ScheduleIndex:
    subtract: int = 0

    def lean(self):
        return f"(i - {self.subtract})" if self.subtract else "i"


@dataclass(frozen=True)
class Reference:
    name: str
    read: object
    index: ScheduleIndex | None = None


@dataclass(frozen=True)
class ByteArray:
    name: str


@dataclass(frozen=True)
class ScheduleArray:
    pass


def word(value):
    require(isinstance(value, Word), "Expected a u64 value in SHA-512 arithmetic")
    return value.lean


class LoopBody:
    """Interpret straight-line LLBC using symbolic UInt64 and bounded index values."""

    def __init__(self, translated, constants, entry):
        self.decls = translated["fun_decls"]
        self.types = translated["type_decls"]
        self.constants = constants
        self.values = dict(entry)
        self.stores = []
        self.writes = []

    def literal(self, node):
        match node:
            case {"Value": [_, [value, _]]}:
                return value
            case {"Deduplicated": index}:
                return self.constants[index]
            case _:
                raise ValueError("Unknown LLBC constant encoding")

    def scalar(self, node):
        match self.literal(node):
            case {"Integer": {"Unsigned": [type_, value]}} | {"Integer": {"Signed": [type_, value]}}:
                return Integer(type_, int(value))
            case _:
                raise ValueError("Expected an LLBC integer constant")

    def place(self, node):
        match node["kind"]:
            case {"Local": index}:
                require(index in self.values, f"Unknown LLBC input local {index}")
                return self.values[index]
            case {"Projection": [inner, "Deref"]}:
                ref = self.place(inner)
                require(isinstance(ref, Reference), "Unsupported LLBC dereference")
                return ref.read
            case {"Projection": [inner, {"Field": [1, 0]}]}:
                payload = self.place(inner)
                require(isinstance(payload, tuple) and payload[0] == "Some", "Expected an Option::Some field")
                return payload[1]
            case {"Projection": [inner, {"Field": [None, index]}]}:
                pair = self.place(inner)
                require(isinstance(pair, tuple) and len(pair) == 2 and 0 <= index < 2,
                        "Expected a field of the iterator pair")
                return pair[index]
            case _:
                raise ValueError(f"Unsupported LLBC place {node['kind']}")

    def operand(self, node):
        match node:
            case {"Copy": place} | {"Move": place}:
                return self.place(place)
            case {"Const": value}:
                return self.scalar(value)
            case _:
                raise ValueError(f"Unsupported LLBC operand {node}")

    def assign(self, dest, value):
        match dest["kind"]:
            case {"Local": index}:
                self.values[index] = value
                self.writes.append(index)
            case {"Projection": [inner, "Deref"]}:
                address = self.place(inner)
                require(isinstance(address, Reference), "Unsupported indirect LLBC write")
                self.stores.append((address, value))
            case _:
                raise ValueError("Unsupported LLBC assignment destination")

    def rvalue(self, node):
        match node:
            case {"Use": [value, "Yes"]}:
                return self.operand(value)
            case {"Ref": {"place": place, "kind": kind}} if kind in ("Shared", "Mut"):
                return Reference(f"local:{local(place)}", self.place(place))
            case {"BinaryOp": [op, left, right]}:
                lhs, rhs = self.operand(left), self.operand(right)
                if op == {"Sub": "Panic"} and isinstance(lhs, ScheduleIndex) and isinstance(rhs, Integer):
                    offset = lhs.subtract + rhs.value
                    require(rhs.type == "Usize" and 0 <= rhs.value and offset <= 16,
                            "Schedule subtraction is outside the verified 16..80 loop range")
                    return ScheduleIndex(offset)
                if op == {"Shr": "Panic"} and isinstance(rhs, Integer):
                    require(rhs.type == "I32" and 0 <= rhs.value < 64, "Invalid u64 shift count")
                    return Word(f"({word(lhs)} >>> {rhs.value})")
                require(op in ("BitXor", "BitAnd"), "Unsupported LLBC binary operation")
                operator = {"BitXor": "^^^", "BitAnd": "&&&"}[op]
                return Word(f"({word(lhs)} {operator} {word(rhs)})")
            case {"UnaryOp": ["Not", value]}:
                return Word(f"(~~~{word(self.operand(value))})")
            case {"Aggregate": [{"Array": [_, size, None]}, values]}:
                require(self.scalar(size) == Integer("Usize", 8) and len(values) == 8,
                        "Expected the eight-word compression register array")
                return tuple(self.operand(item) for item in values)
            case _:
                raise ValueError(f"Unsupported LLBC value {node}")

    def callee(self, call):
        match call["func"]:
            case {"Regular": {"kind": {"Fun": identifier}}}:
                return ident(self.decls[identifier])
            case _:
                raise ValueError("Unsupported indirect LLBC call")

    def call(self, call):
        name = self.callee(call)
        inputs = [self.operand(arg) for arg in call["args"]]
        match name, inputs:
            case ("core", "num", "rotate_right"), [Word(value), Integer("U32", shift)] if 0 <= shift < 64:
                value = Word(f"(rotate {value} {shift})")
            case ("core", "num", "wrapping_add"), [Word(left), Word(right)]:
                value = Word(f"({left} + {right})")
            case ("core", "num", "from_be_bytes"), [ByteArray(array)]:
                bytes_ = [f"({array} {i})" for i in range(8)]
                combined = bytes_[0]
                for byte in bytes_[1:]:
                    combined = f"({combined} ++ {byte})"
                value = Word(f"(UInt64.ofBitVec {combined})")
            case ("core", "array", operation), [Reference(root, ScheduleArray(), None), ScheduleIndex() as i] \
                    if operation in ("index", "index_mut"):
                value = Reference(root, Word(f"(wordAt {i.lean()})"), i)
            case ("core", "array", "index"), [Reference(root, tuple() as values, None), Integer("Usize", i)] \
                    if len(values) == 8 and 0 <= i < 8:
                value = Reference(root, values[i])
            case _:
                raise ValueError(f"Unsupported SHA-512 LLBC call {name} with {inputs}")
        self.assign(call["dest"], value)

    def execute(self, statements, next_kind, payload):
        operations = [row["kind"] for row in statements
                      if not set(row["kind"]) & {"StorageLive", "StorageDead", "Borrowck"}]
        match operations:
            case [{"Assign": [_, {"Ref": _}]}, {"Assign": [_, {"Ref": _}]},
                  {"Call": {"call": next_call}}, {"Switch": switch}, *body, {"Continue": 0}]:
                pass
            case _:
                raise ValueError("Unexpected SHA-512 iterator-loop shape")
        require(self.callee(next_call) == next_kind, "Unexpected SHA-512 iterator kind")
        option = local(next_call["dest"])
        data = switch["data"]
        require(data["fallback"] is None and local(data["scrutinee"]["Discriminant"]) == option and
                len(data["branches"]) == 2 and len(switch["branches"]) == 2,
                "Unexpected SHA-512 Option branch")
        for variant, (constant, branch) in enumerate(data["branches"]):
            match self.literal(constant):
                case {"Discriminant": [{"id": enum}, index]}:
                    require(ident(self.types[enum]) == ("core", "option", "Option") and index == variant,
                            "Unexpected SHA-512 iterator discriminant")
                case _:
                    raise ValueError("Expected an iterator discriminant constant")
            expected = [{"Break": 0}] if variant == 0 else []
            require(branch == variant and
                    [statement["kind"] for statement in switch["branches"][branch]["statements"]] == expected,
                    "Unexpected SHA-512 loop control flow")
        self.values[option] = ("Some", payload)
        for operation in body:
            match operation:
                case {"Assign": [dest, value]}:
                    self.assign(dest, self.rvalue(value))
                case {"Call": {"call": call}}:
                    self.call(call)
                case _:
                    raise ValueError(f"Unsupported LLBC body statement {operation}")


def extract(artifact, target):
    require(artifact["has_errors"] is False, "Charon reported errors in the SHA-512 crate")
    translated = artifact["translated"]
    require(translated["crate_name"] == "abc_sha512" and translated["options"]["start_from"] == ["crate::compress"],
            "Unexpected Charon crate or extraction start point")
    require(len(translated["target_information"]) == 1 and
            translated["target_information"][0]["key"] == target and
            translated["target_information"][0]["value"]["target_pointer_size"] == 8,
            "Expected the requested 64-bit extraction target")
    matches = [d for d in translated["fun_decls"] if d and ident(d) == ("abc_sha512", "compress")]
    require(len(matches) == 1, "Expected one abc_sha512::compress definition")
    signature = matches[0]["signature"]
    require(signature["abi"] == "Rust" and signature["is_unsafe"] is False and len(signature["inputs"]) == 2,
            "Unexpected SHA-512 compression calling convention")
    function = matches[0]["body"]["Structured"]
    loops = [entry["kind"]["Loop"]["statements"] for entry in function["body"]["statements"]
             if "Loop" in entry["kind"]]
    require(len(loops) == 4, "Expected four SHA-512 compression loops")
    names = {item["name"]: item["index"] for item in function["locals"]["locals"]
             if item["name"] in ("words", "work")}
    require(set(names) == {"words", "work"}, "Missing SHA-512 compression arrays")
    literals = {}
    constant_values(matches[0], literals)
    zip_next = ("core", "iter", "adapters", "zip", "next")
    range_next = ("core", "iter", "range", "next")

    load = LoopBody(translated, literals, {})
    load.execute(loops[0], zip_next, (Reference("seed", Word("_old")), Reference("chunk", ByteArray("bytes"))))
    require(len(load.stores) == 1 and load.stores[0][0].name == "seed", "Unexpected SHA-512 seed store")

    schedule = LoopBody(translated, literals, {names["words"]: ScheduleArray()})
    schedule.execute(loops[1], range_next, ScheduleIndex())
    require(len(schedule.stores) == 1, "Expected one SHA-512 schedule store")
    schedule_dest, schedule_word = schedule.stores[0]
    require(schedule_dest.name == f"local:{names['words']}" and isinstance(schedule_dest.index, ScheduleIndex),
            "Unexpected SHA-512 schedule destination")

    work = names["work"]
    initial = tuple(Word(f"state.{component}") for component in "abcdefgh")
    round_ = LoopBody(translated, literals, {work: initial})
    round_.execute(loops[2], zip_next, (Word("constant"), Word("messageWord")))
    resulting = round_.values[work]
    require(not round_.stores and round_.writes.count(work) == 1 and isinstance(resulting, tuple) and
            len(resulting) == 8, "Expected one complete SHA-512 round register update")

    feed = LoopBody(translated, literals, {})
    feed.execute(loops[3], zip_next, (Reference("chain", Word("left")), Word("right")))
    require(len(feed.stores) == 1 and feed.stores[0][0].name == "chain", "Unexpected SHA-512 feed-forward store")
    return (word(load.stores[0][1]), (schedule_dest.index.lean(), word(schedule_word)),
            [word(result) for result in resulting], word(feed.stores[0][1]))


def lean_module(artifact, target):
    load, (index, value), registers, feed = extract(artifact, target)
    fields = ",\n    ".join(registers)
    return f"""import Sha512Compression

namespace Abc.Refine.Sha512.Llbc

open Abc.Spec.Sha512 (Byte)

def load (bytes : Fin 8 → Byte) (_old : UInt64) : UInt64 :=
  {load}

def scheduleStep (wordAt : Nat → UInt64) (i : Nat) : Nat × UInt64 :=
  ({index}, {value})

def roundStep (state : Registers) (constant messageWord : UInt64) : Registers :=
  ⟨{fields}⟩

def feedStep (left right : UInt64) : UInt64 :=
  {feed}

end Abc.Refine.Sha512.Llbc
"""
