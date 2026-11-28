"""Lower the fixed, normal-path Rust Salsa20/8 computation emitted by Charon."""

from tools.verification.keccak.llbc import (
    Cell, Crate, Execution, Iteration, Product, Ref, Scalar, array, function_code, name, require, uint,
)


class SalsaCrate(Crate):
    def __init__(self, artifact, target):
        require(artifact["has_errors"] is False, "Charon reported Salsa20/8 extraction errors")
        self.data = artifact["translated"]
        targets = self.data["target_information"]
        require(self.data["crate_name"] == "abc_scrypt" and self.data["options"]["start_from"] == ["crate::salsa8"] and
                len(targets) == 1 and targets[0]["key"] == target and targets[0]["value"]["target_pointer_size"] == 8,
                "Expected the x86-64 scrypt Salsa20/8 closure")
        self.constants = {}
        self.collect_constants(self.data)
        self.globals = {}

    def declaration(self, section, exported):
        matching = [decl for decl in self.data[section] if decl and name(decl) == ("abc_scrypt", exported)]
        require(len(matching) == 1, f"Expected one scrypt declaration named {exported}")
        return matching[0]

    def literal(self, tag):
        match self.raw(tag):
            case {"Integer": {"Signed": ["I32", value]}}:
                require(-(2**31) <= int(value) < 2**31, "Invalid Salsa20/8 signed loop bound")
                return Scalar("I32", int(value))
            case _:
                return super().literal(tag)


def word(value):
    require(isinstance(value, Scalar) and value.kind == "U32", "Expected a 32-bit Salsa20/8 word")
    return value.lean()


class SalsaExecution(Execution):
    def __init__(self, crate, locals_, bindings, prefix=""):
        super().__init__(crate, locals_)
        self.bindings = bindings
        self.prefix = prefix

    def bind(self, expression):
        symbol = f"{self.prefix}w{len(self.bindings)}"
        self.bindings.append(f"  let {symbol} : BitVec 32 := {expression}")
        return Scalar("U32", symbol)

    def binary(self, operator, lhs, rhs):
        if operator == "BitXor":
            return self.bind(f"{word(lhs)} ^^^ {word(rhs)}")
        return super().binary(operator, lhs, rhs)

    def rvalue(self, node):
        match node:
            case {"Aggregate": [{"Adt": [{"id": kind, "builtin": None}, None, None]}, [first, last]]}:
                require(name(self.crate.data["type_decls"][kind]) == ("core", "ops", "range", "Range"),
                        "Expected an integer range in Salsa20/8")
                lo, hi = self.operand(first), self.operand(last)
                require(lo.kind == hi.kind and lo.kind in ("I32", "Usize") and
                        isinstance(lo.value, int) and isinstance(hi.value, int) and 0 <= lo.value <= hi.value <= 24,
                        "Expected a small, concrete Salsa20/8 range")
                return Iteration("range", (Scalar(lo.kind, i) for i in range(lo.value, hi.value)))
            case _:
                return super().rvalue(node)

    def call(self, call):
        callee, widths = self.crate.callee(call)
        match callee, widths:
            case ("core", "iter", "range", "next"), []:
                [source] = [self.operand(arg) for arg in call["args"]]
                value = self.next(source, "range")
            case ("core", "num", "wrapping_add"), []:
                left, right = map(self.operand, call["args"])
                value = self.bind(f"{word(left)} + {word(right)}")
            case ("core", "num", "rotate_left" | "rotate_right" as rotate), []:
                lane, distance = map(self.operand, call["args"])
                direction = "rotateLeft" if rotate == "rotate_left" else "rotateRight"
                value = self.bind(f"({word(lane)}).{direction} {uint(distance, 'U32')}")
            case ("abc_scrypt", "salsa_quarter"), []:
                state, indices = map(self.operand, call["args"])
                quarter = SalsaExecution(self.crate, {1: state, 2: indices}, self.bindings, self.prefix)
                quarter.function(function_code(self.crate.declaration("fun_decls", "salsa_quarter")))
                value = quarter.locals[0].value
                require(value == Product(()), "Expected Salsa20/8 quarter round to return unit")
            case _:
                return super().call(call)
        self.place(call["dest"]).value = value


def lanes(symbol):
    return array(Scalar("U32", f"({symbol} {i})") for i in range(16))


def output_words(state):
    require(len(state.value) == 16, "Expected sixteen Salsa20/8 words")
    return ["  match index.val with", *(f"  | {i} => {word(lane.value)}" for i, lane in enumerate(state.value)),
            "  | _ => 0"]


def lean_module(artifact, target):
    crate = SalsaCrate(artifact, target)
    state = Cell(lanes("input"))
    execution = SalsaExecution(crate, {1: Ref(state)}, [])
    body = function_code(crate.declaration("fun_decls", "salsa8"))
    loops = [i for i, item in enumerate(body) if "Loop" in item]
    require(len(loops) == 2, "Expected the Salsa20/8 rounds and feed-forward loops")
    start_rounds, _ = loops
    execution.statements(body[:start_rounds])
    copies = [cell for cell in execution.locals.values() if cell.value == state.value]
    require(len(copies) == 1 and copies[0].value is not state.value and not execution.bindings,
            "Expected a separate copy of the original Salsa20/8 state")
    working = copies[0]
    rounds = []

    def iteration(_location, _value, operations):
        prefix = f"rd{len(rounds)}_"
        execution.prefix = prefix
        execution.bindings = []
        for cell, new in zip(working.value, lanes("working"), strict=True):
            cell.value = new.value
        execution.statements(operations)
        require(state.value == lanes("input"), "A Salsa20/8 round changed the original state")
        rounds.append([line.replace(prefix, "") for line in (*execution.bindings, *output_words(working))])

    execution.run_loop(body[start_rounds]["Loop"], iteration)
    require(rounds and all(round_ == rounds[0] for round_ in rounds), "Salsa20/8 round bodies differ")
    for cell, new in zip(working.value, lanes("tail"), strict=True):
        cell.value = new.value
    execution.prefix = "feed_"
    execution.bindings = []
    execution.function(body[start_rounds + 1:])
    require(execution.locals[0].value == Product(()), "Expected Salsa20/8 to return unit")
    application = "input"
    for _ in rounds:
        application = f"(sourceDoubleRound {application})"
    return "\n".join([
        "namespace Abc.Refine.Scrypt.Source", "",
        "def sourceDoubleRound (working : Fin 16 → BitVec 32) (index : Fin 16) : BitVec 32 :=",
        *rounds[0], "",
        "def sourceFeed (input tail : Fin 16 → BitVec 32) (index : Fin 16) : BitVec 32 :=",
        *execution.bindings, *output_words(state), "",
        "def sourceSalsa8 (input : Fin 16 → BitVec 32) : Fin 16 → BitVec 32 :=",
        f"  sourceFeed input {application}", "",
        "end Abc.Refine.Scrypt.Source", "",
    ])
