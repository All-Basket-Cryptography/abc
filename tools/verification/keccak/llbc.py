"""Lower the normal paths of the Keccak Rust crate's fixed-width LLBC."""

from dataclasses import dataclass


def require(condition, message):
    if not condition:
        raise ValueError(message)


def name(declaration):
    return tuple(item["Ident"][0] for item in declaration["item_meta"]["name"] if "Ident" in item)


def code(block):
    return [statement["kind"] for statement in block["statements"]
            if not set(statement["kind"]) & {"StorageLive", "StorageDead", "Borrowck"}]


@dataclass(frozen=True)
class Scalar:
    kind: str
    value: int | str

    def lean(self):
        return str(self.value) if isinstance(self.value, str) else f"({self.value} : BitVec {self.kind[1:]})"


@dataclass
class Cell:
    value: object


@dataclass(frozen=True)
class Ref:
    cell: Cell


@dataclass(frozen=True)
class Product:
    fields: tuple[Cell, ...]


@dataclass(frozen=True)
class Option:
    item: Cell | None


@dataclass
class Iteration:
    kind: str
    items: object


def array(values):
    return [Cell(value) for value in values]


def copy(value):
    if isinstance(value, list):
        return array(copy(cell.value) for cell in value)
    return value


def uint(value, kind):
    require(isinstance(value, Scalar) and value.kind == kind and isinstance(value.value, int),
            f"Expected a concrete {kind}")
    return value.value


def reference(value):
    require(isinstance(value, Ref), "Expected a Keccak reference")
    return value.cell


def slice_cells(value):
    cells = reference(value).value
    require(isinstance(cells, list), "Expected a Keccak slice or fixed array")
    return cells


def word(value):
    require(isinstance(value, Scalar) and value.kind == "U64", "Expected a Keccak lane")
    return value


def xor(left, right):
    left, right = word(left), word(right)
    if left.value == 0:
        return right
    return Scalar("U64", f"({left.lean()} ^^^ {right.lean()})")


class Crate:
    def __init__(self, artifact, target):
        require(artifact["has_errors"] is False, "Charon reported Keccak extraction errors")
        self.data = artifact["translated"]
        targets = self.data["target_information"]
        require(self.data["crate_name"] == "abc_keccak_p1600" and
                self.data["options"]["start_from"] == ["crate::absorb_rate_block"] and
                len(targets) == 1 and targets[0]["key"] == target and targets[0]["value"]["target_pointer_size"] == 8,
                "Expected the x86-64 Keccak absorb closure")
        self.constants = {}
        self.collect_constants(self.data)
        self.globals = {}

    def collect_constants(self, item):
        if isinstance(item, dict):
            match item:
                case {"Value": [index, [payload, _]]}:
                    self.constants[index] = payload
            for child in item.values():
                self.collect_constants(child)
        elif isinstance(item, list):
            for child in item:
                self.collect_constants(child)

    def raw(self, tag):
        match tag:
            case {"Value": [_, [payload, _]]}:
                return payload
            case {"Deduplicated": index}:
                return self.constants[index]
            case _:
                raise ValueError("Unexpected Keccak LLBC literal")

    def literal(self, tag):
        match self.raw(tag):
            case {"Integer": {"Unsigned": [kind, value]}}:
                return Scalar(kind, int(value))
            case _:
                raise ValueError("Expected a Keccak unsigned LLBC literal")

    def declaration(self, section, exported):
        matches = [decl for decl in self.data[section] if decl and name(decl) == ("abc_keccak_p1600", exported)]
        require(len(matches) == 1, f"Expected one Keccak declaration named {exported}")
        return matches[0]

    def global_value(self, index):
        if index not in self.globals:
            declaration = self.data["global_decls"][index]
            match self.raw(declaration["value"]):
                case {"Call": [{"kind": {"Fun": initializer}}, []]}:
                    model = Execution(self, {})
                    model.function(function_code(self.data["fun_decls"][initializer]))
                    self.globals[index] = model.locals[0]
                case _:
                    self.globals[index] = Cell(self.literal(declaration["value"]))
        return self.globals[index]

    def callee(self, call):
        match call["func"]:
            case {"Regular": {"kind": {"Fun": index}, "generics": generics}}:
                widths = [uint(self.literal(tag), "Usize") for tag in generics["const_generics"]]
                return name(self.data["fun_decls"][index]), widths
            case _:
                raise ValueError("Unexpected indirect Keccak LLBC call")


def function_code(declaration):
    signature = declaration["signature"]
    require(signature["abi"] == "Rust" and signature["is_unsafe"] is False,
            "Expected safe Rust Keccak LLBC")
    return code(declaration["body"]["Structured"]["body"])


def elements(source):
    if isinstance(source, Ref):
        return (Ref(cell) for cell in slice_cells(source))
    if isinstance(source, list):
        return (copy(cell.value) for cell in source)
    if isinstance(source, Iteration):
        return source.items
    raise ValueError("Expected a Keccak iterable")


def split_chunks(source, width):
    cells = slice_cells(source)
    require(width > 0, "Cannot split a Keccak slice into zero-width chunks")
    end = len(cells) - len(cells) % width
    chunks = array(cells[i:i + width] for i in range(0, end, width))
    return Product((Cell(Ref(Cell(chunks))), Cell(Ref(Cell(cells[end:])))))


class Execution:
    def __init__(self, crate, locals_):
        self.crate = crate
        self.locals = {index: Cell(value) for index, value in locals_.items()}
        self.permutations = 0

    def place(self, node):
        match node["kind"]:
            case {"Local": index}:
                return self.locals.setdefault(index, Cell(None))
            case {"Global": {"id": index}}:
                return self.crate.global_value(index)
            case {"Projection": [inner, "Deref"]}:
                return reference(self.place(inner).value)
            case {"Projection": [inner, {"Field": [None, index]}]}:
                value = self.place(inner).value
                require(isinstance(value, Product), "Unexpected Keccak tuple projection")
                return value.fields[index]
            case {"Projection": [inner, {"Field": [1, 0]}]}:
                value = self.place(inner).value
                require(isinstance(value, Option) and value.item is not None, "Expected a Keccak Some payload")
                return value.item
            case _:
                raise ValueError(f"Unsupported Keccak LLBC place {node['kind']}")

    def operand(self, operand):
        match operand:
            case {"Copy": place}:
                return copy(self.place(place).value)
            case {"Move": place}:
                return self.place(place).value
            case {"Const": tag}:
                return self.crate.literal(tag)
            case _:
                raise ValueError("Unexpected Keccak LLBC operand")

    def binary(self, operator, lhs, rhs):
        match operator:
            case "BitXor":
                return xor(lhs, rhs)
            case "BitAnd" | "BitOr":
                operator = "&&&" if operator == "BitAnd" else "|||"
                return Scalar("U64", f"({word(lhs).lean()} {operator} {word(rhs).lean()})")
            case {"Add": "Panic"} | {"Mul": "Panic"} | {"Rem": "Panic"}:
                a, b = uint(lhs, "Usize"), uint(rhs, "Usize")
                if "Add" in operator:
                    result = a + b
                elif "Mul" in operator:
                    result = a * b
                else:
                    require(b != 0, "Keccak index remainder divides by zero")
                    result = a % b
                require(0 <= result < 2**64, "Keccak index operation overflows usize")
                return Scalar("Usize", result)
            case _:
                raise ValueError(f"Unsupported Keccak LLBC operator {operator}")

    def rvalue(self, node):
        match node:
            case {"Use": [operand, "Yes" | "No"]}:
                return self.operand(operand)
            case {"Ref": {"place": place, "kind": "Shared" | "Mut" | "TwoPhaseMut"}}:
                return Ref(self.place(place))
            case {"BinaryOp": [operator, lhs, rhs]}:
                return self.binary(operator, self.operand(lhs), self.operand(rhs))
            case {"UnaryOp": ["Not", value]}:
                return Scalar("U64", f"(~~~{word(self.operand(value)).lean()})")
            case {"Aggregate": [{"Array": [_, length, None]}, operands]}:
                require(uint(self.crate.literal(length), "Usize") == len(operands), "Bad Keccak LLBC array width")
                return array(self.operand(operand) for operand in operands)
            case {"Aggregate": [{"Adt": [{"builtin": "Tuple"}, None, None]}, []]}:
                return Product(())
            case _:
                raise ValueError(f"Unsupported Keccak LLBC value {node}")

    def call(self, call):
        callee, widths = self.crate.callee(call)
        args = [self.operand(arg) for arg in call["args"]]
        value = Product(())
        match callee, widths, args:
            case ("core", "array", "repeat"), [width], [initial]:
                value = array(copy(initial) for _ in range(width))
            case ("core", "array", "as_slice" | "as_mut_slice"), [width], [source]:
                require(len(slice_cells(source)) == width, "Keccak array-to-slice width mismatch")
                value = source
            case ("core", "slice", "as_chunks" | "as_chunks_mut"), [width], [source]:
                value = split_chunks(source, width)
            case ("core", "array", "index" | "index_mut"), [width], [source, index]:
                cells = slice_cells(source)
                require(len(cells) == width, "Keccak fixed array width mismatch")
                i = uint(index, "Usize")
                require(0 <= i < width, "Keccak LLBC index out of range")
                value = Ref(cells[i])
            case ("core", "slice", "iter" | "iter_mut"), [], [source]:
                value = Iteration("slice", iter(elements(source)))
            case ("core", "slice", "iter", "into_iter"), [], [source]:
                value = Iteration("slice", iter(elements(source)))
            case ("core", "array", "iter", "into_iter"), [width], [list() as source]:
                require(len(source) == width, "Keccak array iterator width mismatch")
                value = Iteration("array", iter(elements(source)))
            case ("core", "iter", "traits", "collect", "into_iter"), [], [Iteration() as iterator]:
                value = iterator
            case ("core", "iter", "traits", "iterator", "Iterator", "zip"), [], [left, right]:
                value = Iteration("zip", (Product((Cell(a), Cell(b))) for a, b in zip(elements(left), elements(right))))
            case ("core", "iter", "traits", "iterator", "Iterator", "enumerate"), [], [source]:
                value = Iteration("enumerate", (Product((Cell(Scalar("Usize", i)), Cell(item)))
                                                for i, item in enumerate(elements(source))))
            case ("core", "slice", "iter", "next"), [], [iterator]:
                value = self.next(iterator, "slice")
            case ("core", "array", "iter", "next"), [_], [iterator]:
                value = self.next(iterator, "array")
            case ("core", "iter", "adapters", "zip" | "enumerate" as kind, "next"), [], [iterator]:
                value = self.next(iterator, kind)
            case ("core", "num", "rotate_left" | "rotate_right" as rotate), [], [lane, distance]:
                direction = "rotateLeft" if rotate == "rotate_left" else "rotateRight"
                value = Scalar("U64", f"({word(lane).lean()}).{direction} {uint(distance, 'U32')}")
            case ("core", "ops", "bit", "bitxor_assign"), [], [location, source]:
                cell = reference(location)
                cell.value = xor(cell.value, reference(source).value if isinstance(source, Ref) else source)
            case ("core", "num", "from_le_bytes" | "from_be_bytes" as conversion), [], [list() as source]:
                require(len(source) == 8, "Keccak lane conversion must consume eight bytes")
                bytes_ = [cell.value for cell in source]
                require(all(isinstance(byte, Scalar) and byte.kind == "U8" for byte in bytes_),
                        "Keccak lane conversion did not receive bytes")
                if conversion == "from_be_bytes":
                    bytes_.reverse()
                cases = " | ".join(f"{i} => {byte.lean()}" for i, byte in enumerate(bytes_))
                value = Scalar("U64", f"(packLE 8 (fun i => match i with | {cases} | _ => 0))")
            case ("abc_keccak_p1600", "keccak_p1600"), [], [state]:
                require(reference(state) is reference(self.locals[1].value) and self.permutations == 0,
                        "Expected a single final permutation of the Keccak state")
                self.permutations += 1
            case _:
                raise ValueError(f"Unsupported Keccak LLBC call {callee} {widths}")
        self.place(call["dest"]).value = value

    def next(self, iterator, kind):
        source = reference(iterator).value
        require(isinstance(source, Iteration) and source.kind == kind, "Keccak iterator dispatch mismatch")
        item = next(source.items, None)
        return Option(None if item is None else Cell(item))

    def statements(self, statements):
        for node in statements:
            if self.permutations:
                match node:
                    case {"Assign": [{"kind": {"Local": 0}}, _]}:
                        pass
                    case _:
                        raise ValueError("Unexpected Keccak work after the final permutation")
            match node:
                case {"Assign": [dest, value]}:
                    self.place(dest).value = self.rvalue(value)
                case {"Call": {"call": call}}:
                    self.call(call)
                case {"Loop": loop}:
                    self.run_loop(loop)
                case {"Drop": {"place": place}}:
                    require(isinstance(self.place(place).value, Iteration), "Unexpected Keccak destructor")
                case _:
                    raise ValueError(f"Unsupported Keccak LLBC statement {node}")

    def function(self, statements):
        require(statements[-1] == "Return", "Expected a normal Keccak return")
        self.statements(statements[:-1])

    def option_switch(self, switch):
        data = switch["data"]
        option = self.place(data["scrutinee"]["Discriminant"]).value
        require(isinstance(option, Option) and data["fallback"] is None and len(data["branches"]) == 2 and
                len(switch["branches"]) == 2, "Unexpected Keccak Option switch")
        arms = {}
        for tag, index in data["branches"]:
            match self.crate.raw(tag):
                case {"Discriminant": [{"id": enum}, variant]}:
                    require(name(self.crate.data["type_decls"][enum]) == ("core", "option", "Option"),
                            "Expected the Rust Option discriminant")
                    arms[variant] = index
                case _:
                    raise ValueError("Unexpected Keccak switch literal")
        require(set(arms) == {0, 1} and sorted(arms.values()) == [0, 1] and
                code(switch["branches"][arms[0]]) == [{"Break": 0}] and not code(switch["branches"][arms[1]]),
                "Unexpected Keccak iterator branch control flow")
        return data["scrutinee"]["Discriminant"], option

    def run_loop(self, loop, on_iteration=None):
        operations = code(loop)
        branch = next(i for i, node in enumerate(operations) if "Switch" in node)
        require(operations[-1] == {"Continue": 0}, "Expected Keccak loop continuation")
        for _ in range(26):
            self.statements(operations[:branch])
            location, option = self.option_switch(operations[branch]["Switch"])
            if option.item is None:
                return
            if on_iteration:
                on_iteration(location, option.item, operations[branch + 1:-1])
            else:
                self.statements(operations[branch + 1:-1])
        raise ValueError("Keccak loop did not finish within its fixed-size domain")


def state_variables():
    return array(Scalar("U64", f"state {i}") for i in range(25))


def observe_round(crate):
    body = function_code(crate.declaration("fun_decls", "keccak_p1600"))
    loops = [i for i, statement in enumerate(body) if "Loop" in statement]
    require(len(loops) == 1, "Expected one outer Keccak round iterator")
    [loop] = loops
    state = Cell(state_variables())
    model = Execution(crate, {1: Ref(state)})
    model.statements(body[:loop])
    require(state.value == state_variables(), "Keccak prelude changed the input lanes")
    constants, rounds = [], []

    def iteration(location, constant, statements):
        require(state.value == state_variables(), "The round iterator changed the input lanes")
        [item_local] = location["kind"].values()
        require("Local" in location["kind"] and item_local not in (0, 1), "Unexpected Keccak round item local")
        constants.append(uint(constant.value, "U64"))
        symbolic_state = Cell(state_variables())
        symbolic_constant = Option(Cell(Scalar("U64", "constant")))
        round_model = Execution(crate, {1: Ref(symbolic_state), item_local: symbolic_constant})
        round_model.statements(statements)
        require(round_model.permutations == 0, "Unexpected recursive permutation in a Keccak round")
        rounds.append([word(lane.value).lean() for lane in symbolic_state.value])

    model.run_loop(body[loop]["Loop"], iteration)
    require(len(constants) == 24 and all(round_ == rounds[0] for round_ in rounds),
            "Expected all 24 Keccak iterations to apply one round shape")
    require(state.value == state_variables(), "The round iterator changed the input lanes")
    model.function(body[loop + 1:])
    require(state.value == state_variables() and model.locals[0].value == Product(()) and model.permutations == 0,
            "Unexpected Keccak permutation epilogue")
    return constants, rounds[0]


def observe_absorb(crate):
    body = function_code(crate.declaration("fun_decls", "absorb_rate_block"))
    state = Cell(state_variables())
    block = Cell(array(Scalar("U8", f"block {i}") for i in range(136)))
    model = Execution(crate, {1: Ref(state), 2: Ref(block)})
    model.function(body)
    require(model.permutations == 1 and model.locals[0].value == Product(()),
            "Expected Keccak absorb to apply exactly one final permutation")
    return [word(lane.value).lean() for lane in state.value]


def lean_module(artifact, target):
    crate = Crate(artifact, target)
    constants, lanes = observe_round(crate)
    absorbed = observe_absorb(crate)
    constant_values = ", ".join(f"0x{constant:016x}" for constant in constants)

    def arms(expressions):
        return "\n".join(f"  | {i} => {term}" for i, term in enumerate(expressions))

    return f"""import KeccakRound

namespace Abc.Refine.Keccak.Source

open Abc.Spec.KeccakRound

def sourceConstants (round : RoundIndex) : Lane :=
  #[{constant_values}][round.val]!

def sourceRound (state : State) (constant : Lane) (lane : LaneIndex) : Lane :=
  match lane.val with
{arms(lanes)}
  | _ => 0

def sourceAbsorbMix (state : State) (block : Block) (lane : LaneIndex) : Lane :=
  match lane.val with
{arms(absorbed)}
  | _ => 0

def sourcePermutation (state : State) : State :=
  (List.finRange 24).foldl (fun lanes round => sourceRound lanes (sourceConstants round)) state

def sourceAbsorb (state : State) (block : Block) : State :=
  sourcePermutation (sourceAbsorbMix state block)

end Abc.Refine.Keccak.Source
"""
