"""Translate the supported, effect-free Charon LLBC subset for the GHASH loop."""

from dataclasses import dataclass


def require(test, detail):
    if not test:
        raise ValueError(detail)


def tagged(term):
    if isinstance(term, str):
        return term, None
    require(isinstance(term, dict) and len(term) == 1, f"Expected a single LLBC tag: {term}")
    return next(iter(term.items()))


def name_segments(declaration):
    return declaration["item_meta"]["name"]


def ident(name):
    return {"Ident": [name, 0]}


@dataclass(frozen=True)
class Expression:
    code: str
    ty: int | str


class ScalarLoop:
    def __init__(self, llbc):
        require(llbc["charon_version"] == "0.1.254" and llbc["has_errors"] is False,
                "Expected complete LLBC from the pinned Charon release")
        crate = llbc["translated"]
        require(crate["crate_name"] == "abc_aes256_gcm", "Unexpected source crate")
        self.types = {}
        self.constants = {}
        self.collect_definitions(crate)
        functions = [entry for entry in crate["fun_decls"] if entry is not None]
        self.functions = {entry["def_id"]: entry for entry in functions}
        source = [entry for entry in functions
                  if name_segments(entry) == [ident("abc_aes256_gcm"), ident("multiply")]]
        require(len(source) == 1 and source[0]["item_meta"]["is_local"] is True,
                "Expected one local GHASH multiply")
        source = source[0]
        self.signature(source, [128, 128], 128)
        self.body = source["body"]["Structured"]
        require(self.body["bound_body_regions"] == 0 and self.body["locals"]["arg_count"] == 2,
                "Unexpected function body arguments")
        locals_ = self.body["locals"]["locals"]
        self.locals = {local["index"]: self.scalar_type(local["ty"]) for local in locals_}
        named = {local["name"]: local["index"] for local in locals_ if local["name"] is not None}
        require(named.get("input") == 1 and named.get("key") == 2, "Unexpected input locals")
        self.product, self.bit = named["product"], named["bit"]
        require([self.locals[k] for k in (0, 1, 2, self.product, self.bit)] == [128, 128, 128, 128, 32],
                "Unexpected live GHASH state types")

    def collect_definitions(self, term):
        if isinstance(term, dict):
            if "Value" in term and isinstance(term["Value"], list) and len(term["Value"]) == 2:
                index, value = term["Value"]
                if isinstance(value, dict) and set(value) == {"Scalar"}:
                    require(index not in self.types or self.types[index] == value, "Conflicting LLBC scalar types")
                    self.types[index] = value
                if (isinstance(value, list) and len(value) == 2 and isinstance(value[0], dict)
                        and set(value[0]) in ({"Integer"}, {"Bool"})):
                    require(index not in self.constants or self.constants[index] == value,
                            "Conflicting LLBC scalar constants")
                    self.constants[index] = value
            for child in term.values():
                self.collect_definitions(child)
        elif isinstance(term, list):
            for child in term:
                self.collect_definitions(child)

    def scalar_type(self, reference):
        tag, data = tagged(reference)
        require(tag in ("Value", "Deduplicated"), f"Unsupported scalar type reference: {tag}")
        value = data[1] if tag == "Value" else self.types[data]
        scalar = value["Scalar"]
        if scalar == "Bool":
            return "Bool"
        width = scalar["Integer"]["Unsigned"]
        require(width in ("U128", "U32"), f"Unsupported LLBC scalar type {scalar}")
        return int(width[1:])

    def signature(self, function, args, output):
        sig = function["signature"]
        require(not sig["is_unsafe"] and not sig["is_variadic"] and sig["abi"] == "Rust"
                and not any(function["generics"].values())
                and [self.scalar_type(ty) for ty in sig["inputs"]] == args
                and self.scalar_type(sig["output"]) == output, "Unexpected scalar function signature")

    def local_index(self, place):
        tag, index = tagged(place["kind"])
        require(tag == "Local", "This translator supports unprojected scalar locals")
        require(self.locals[index] == self.scalar_type(place["ty"]), "Local scalar type changed")
        return index

    def constant(self, reference):
        tag, data = tagged(reference)
        require(tag in ("Value", "Deduplicated"), f"Unsupported constant reference: {tag}")
        value, reference_type = data[1] if tag == "Value" else self.constants[data]
        ty = self.scalar_type(reference_type)
        if ty == "Bool":
            require(type(value["Bool"]) is bool, "Unexpected Boolean literal")
            return Expression(str(value["Bool"]).lower(), ty)
        integer, digits = value["Integer"]["Unsigned"]
        number = int(digits)
        require(integer == f"U{ty}" and 0 <= number < 2**ty, "Unexpected integer literal")
        return Expression(f"{number}#{ty}", ty)

    def operand(self, env, operand):
        tag, data = tagged(operand)
        if tag == "Const":
            return self.constant(data)
        require(tag in ("Copy", "Move"), f"Unsupported LLBC operand: {tag}")
        index = self.local_index(data)
        require(index in env, f"Use of local {index} outside its translated scope")
        return env[index]

    def arithmetic(self, env, value, checks):
        tag, data = tagged(value)
        if tag == "Use":
            require(data[1] == "Yes", "Unexpected non-initializing assignment")
            return self.operand(env, data[0])
        require(tag == "BinaryOp", f"Unsupported LLBC expression: {tag}")
        operator, lhs, rhs = data
        op, overflow = tagged(operator)
        left, right = self.operand(env, lhs), self.operand(env, rhs)
        lval, rval = left.code, right.code
        if op == "Shr":
            require(overflow == "Panic" and left.ty == 128 and right.ty == 32, "Unexpected shift")
            checks.append(f"({rval}).toNat < 128")
            return Expression(f"({lval} >>> ({rval}).toNat)", 128)
        require(left.ty == right.ty and left.ty in (32, 128), "Binary operand type mismatch")
        if op == "Sub":
            require(overflow == "Panic" and left.ty == 32, "Unexpected checked subtraction")
            checks.append(f"({rval}).toNat ≤ ({lval}).toNat")
            return Expression(f"({lval} - {rval})", 32)
        symbol = {"Ne": "!=", "BitAnd": "&&&", "BitXor": "^^^"}.get(op)
        require(overflow is None and symbol is not None, f"Unsupported LLBC operator: {op}")
        return Expression(f"({lval} {symbol} {rval})", "Bool" if op == "Ne" else left.ty)

    def wrapping_sub(self, env, item):
        call = item["call"]
        pointer = call["func"]["Regular"]
        fn = self.functions[pointer["kind"]["Fun"]]
        path = name_segments(fn)
        require(len(path) == 4 and path[:2] == [ident("core"), ident("num")]
                and path[3] == ident("wrapping_sub") and not any(pointer["generics"].values())
                and fn["body"] == "Opaque", "Unsupported LLBC call")
        implementation = path[2]["Impl"]["Ty"]
        require(implementation["kind"] == "InherentImplBlock" and not any(implementation["params"].values())
                and self.scalar_type(implementation["skip_binder"]) == 128,
                "Expected the standard u128 wrapping subtraction")
        self.signature(fn, [128, 128], 128)
        require(len(call["args"]) == 2, "Wrong subtraction arity")
        args = [self.operand(env, arg) for arg in call["args"]]
        require([item.ty for item in args] == [128, 128], "Wrong subtraction operand type")
        cleanup = self.statements(item["on_unwind"])
        require(cleanup == [("UnwindResume", None)], "Unexpected cleanup in wrapping subtraction")
        return self.local_index(call["dest"]), Expression(f"({args[0].code} - {args[1].code})", 128)

    def statements(self, block):
        result = []
        for statement in block["statements"]:
            tag, args = tagged(statement["kind"])
            if tag in ("StorageLive", "StorageDead"):
                require(args in self.locals, "Storage operation on an unknown scalar")
            elif tag == "Borrowck":
                self.local_index(args["FakeRead"])
            else:
                result.append((tag, args))
        return result

    def execute(self, env, statements):
        env = dict(env)
        checks = []
        for tag, args in statements:
            if tag == "Assign":
                index, value = self.local_index(args[0]), self.arithmetic(env, args[1], checks)
            elif tag == "Call":
                index, value = self.wrapping_sub(env, args)
            else:
                raise ValueError(f"Unsupported statement inside scalar block: {tag}")
            require(value.ty == self.locals[index], "Assignment type mismatch")
            env[index] = value
        return env, checks

    def translate(self):
        statements = self.statements(self.body["body"])
        loops = [index for index, (tag, _) in enumerate(statements) if tag == "Loop"]
        require(len(loops) == 1 and statements[-1] == ("Return", None), "Expected one top-level loop and return")
        top = loops[0]
        input_, key = Expression("_input", 128), Expression("_key", 128)
        initial, setup_checks = self.execute({1: input_, 2: key}, statements[:top])
        require(not setup_checks and initial[1] == input_ and initial[2] == key, "Unsupported GHASH initialization")
        loop = self.statements(statements[top][1])
        require(loop[-1][0] == "Switch", "Expected a guarded source loop")
        state = {1: input_, 2: key, self.bit: Expression("_bit", 32), self.product: Expression("_product", 128)}
        guard_state, guard_checks = self.execute(state, loop[:-1])
        require(not guard_checks and all(guard_state[k] == v for k, v in state.items()),
                "Unexpected modification during loop guard evaluation")
        switch = loop[-1][1]
        data = switch["data"]
        condition = self.operand(guard_state, data["scrutinee"]["Value"])
        ((case_value, stop),) = data["branches"]
        start = data["fallback"]
        require(condition.ty == "Bool" and self.constant(case_value) == Expression("false", "Bool")
                and len(switch["branches"]) == 2 and {start, stop} == {0, 1},
                "Unsupported branch structure in source loop")
        then = self.statements(switch["branches"][start])
        otherwise = self.statements(switch["branches"][stop])
        require(then[-1] == ("Continue", 0) and otherwise == [("Break", 0)], "Unexpected loop control")
        updated, step_checks = self.execute(guard_state, then[:-1])
        require(updated[1] == input_, "Unsupported mutation of the GHASH input")
        ended, exit_checks = self.execute(state, statements[top + 1:-1])
        require(not exit_checks, "Unsupported arithmetic check in the exit block")
        state_type = "BitVec 32 × BitVec 128 × BitVec 128"
        args = "(_input : BitVec 128) (_bit : BitVec 32) (_product _key : BitVec 128)"
        step_state = f"({updated[self.bit].code}, {updated[self.product].code}, {updated[2].code})"
        checks = " ∧ ".join(step_checks) or "True"
        return f"""import Std

namespace Abc.Extracted.Ghash

def initial (_input _key : BitVec 128) : {state_type} :=
  ({initial[self.bit].code}, {initial[self.product].code}, _key)

def continues {args} : Bool :=
  {condition.code}

def step {args} : Option ({state_type}) :=
  if {checks} then
    some {step_state}
  else none

def exited {args} : BitVec 128 :=
  {ended[0].code}

def run (_input : BitVec 128) : Nat → {state_type} → Option (BitVec 128)
  | 0, (_bit, _product, _key) =>
    if continues _input _bit _product _key then none else some (exited _input _bit _product _key)
  | fuel + 1, (_bit, _product, _key) =>
    if continues _input _bit _product _key then
      match step _input _bit _product _key with
      | none => none
      | some updated => run _input fuel updated
    else some (exited _input _bit _product _key)

def multiply (_input _key : BitVec 128) : Option (BitVec 128) :=
  let state := initial _input _key
  run _input state.1.toNat state

end Abc.Extracted.Ghash
"""


def translate(llbc):
    return ScalarLoop(llbc).translate()
