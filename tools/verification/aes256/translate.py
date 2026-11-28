"""Translate the byte-field operations in the pinned AES provider LLBC."""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def tag(term):
    if isinstance(term, str):
        return term, None
    require(isinstance(term, dict) and len(term) == 1, "Expected a single LLBC tag")
    return next(iter(term.items()))


def ident(name):
    return {"Ident": [name, 0]}


def path(function):
    return function["item_meta"]["name"]


def statements(block):
    ignored = {"StorageLive", "StorageDead", "Borrowck"}
    return [(name, value) for item in block["statements"] for name, value in [tag(item["kind"])] if name not in ignored]


class ByteOperations:
    WIDTHS = {"U8": 8, "U16": 16}

    def __init__(self, input_):
        require(input_["charon_version"] == "0.1.254" and input_["has_errors"] is False, "Invalid Charon extraction")
        crate = input_["translated"]
        require(crate["crate_name"] == "abc_aes256", "Expected the portable Rust AES provider")
        self.functions = {entry["def_id"]: entry for entry in crate["fun_decls"] if entry}
        self.types, self.constants = {}, {}
        self.collect(crate)

    def collect(self, term):
        if isinstance(term, dict):
            entry = term.get("Value")
            if isinstance(entry, list) and len(entry) == 2:
                index, value = entry
                if isinstance(value, dict) and set(value) == {"Scalar"}:
                    self.types[index] = value
                elif isinstance(value, list) and len(value) == 2 and isinstance(value[0], dict) and "Integer" in value[0]:
                    self.constants[index] = value
            for value in term.values():
                self.collect(value)
        elif isinstance(term, list):
            for value in term:
                self.collect(value)

    def local(self, name):
        (function,) = [item for item in self.functions.values() if path(item) == [ident("abc_aes256"), ident(name)]]
        require(function["item_meta"]["is_local"] is True, f"Expected source function {name}")
        return function

    def type_(self, reference):
        kind, value = tag(reference)
        require(kind in ("Value", "Deduplicated"), "Unexpected type reference")
        return (value[1] if kind == "Value" else self.types[value])["Scalar"]["Integer"]

    def width(self, reference):
        return self.WIDTHS[self.type_(reference)["Unsigned"]]

    def number(self, operand):
        kind, reference = tag(operand["Const"])
        require(kind in ("Value", "Deduplicated"), "Unexpected constant reference")
        constant, ty = reference[1] if kind == "Value" else self.constants[reference]
        (signedness, (kind, digits)), = constant["Integer"].items()
        require(self.type_(ty) == {signedness: kind}, "Constant type mismatch")
        return kind, int(digits)

    def value(self, env, operand):
        operation, place = tag(operand)
        if operation == "Const":
            ty, number = self.number(operand)
            width = self.WIDTHS[ty]
            require(0 <= number < 2**width, "Out-of-range byte-field literal")
            return f"{number}#{width}", width
        require(operation in ("Move", "Copy"), "Unsupported byte-field operand")
        code, width = env[place["kind"]["Local"]]
        require(width == self.width(place["ty"]), "Inconsistent byte-field operand width")
        return code, width

    def rvalue(self, env, raw):
        kind, operands = tag(raw)
        if kind == "Use":
            require(operands[1] == "Yes", "Expected a live byte-field value")
            return self.value(env, operands[0])
        if kind == "UnaryOp":
            cast, operand = operands
            require(cast == {"Cast": {"Scalar": [{"Integer": {"Unsigned": "U16"}}, {"Integer": {"Unsigned": "U8"}}]}},
                    "Unsupported byte-field cast")
            code, width = self.value(env, operand)
            require(width == 16, "Expected word truncation")
            return f"({code}).truncate 8", 8
        require(kind == "BinaryOp", "Unsupported byte-field expression")
        raw_op, left, right = operands
        op, overflow = tag(raw_op)
        left, width = self.value(env, left)
        if op in ("Shl", "Shr"):
            ty, amount = self.number(right)
            require(ty == "I32" and overflow == "Panic" and 0 <= amount < width, "Unsafe byte-field shift")
            symbol = {"Shl": "<<<", "Shr": ">>>"}[op]
            return f"({left} {symbol} {amount})", width
        right, right_width = self.value(env, right)
        require(overflow is None and width == right_width, "Unexpected bitwise operands")
        symbol = {"BitAnd": "&&&", "BitOr": "|||", "BitXor": "^^^"}[op]
        return f"({left} {symbol} {right})", width

    def call(self, env, item):
        call = item["call"]
        pointer = call["func"]["Regular"]
        function = self.functions[pointer["kind"]["Fun"]]
        name = path(function)
        require(meaningful_cleanup(item) and not any(pointer["generics"].values()), "Unexpected byte-field call shape")
        sig = function["signature"]
        args = [self.value(env, operand) for operand in call["args"]]
        widths = [width for _, width in args]
        require(widths == [self.width(ty) for ty in sig["inputs"]], "Wrong byte-field call arguments")
        output = self.width(sig["output"])
        if name[:2] == [ident("core"), ident("num")] and name[-1] == ident("wrapping_sub"):
            require(widths == [8, 8] and output == 8 and self.width(name[2]["Impl"]["Ty"]["skip_binder"]) == 8,
                    "Expected standard u8 wrapping subtraction")
            result = f"({args[0][0]} - {args[1][0]})"
        elif function is self.local("mul_x") and widths == [8] and output == 8:
            result = f"mulX {args[0][0]}"
        else:
            require(name[:3] == list(map(ident, ("core", "convert", "num"))) and name[-1] == ident("from")
                    and "Trait" in name[-2]["Impl"] and widths == [8] and output == 16,
                    "Expected the standard u8-to-u16 From implementation")
            result = f"({args[0][0]}).zeroExtend 16"
        return call["dest"], (result, output)

    def emit(self, source, lean):
        function = self.local(source)
        signature = function["signature"]
        require(signature["abi"] == "Rust" and not signature["is_unsafe"] and not signature["is_variadic"]
                and [self.width(ty) for ty in signature["inputs"]] == [8] and self.width(signature["output"]) == 8,
                "Wrong byte-field signature")
        body = function["body"]["Structured"]
        require(body["locals"]["arg_count"] == 1 and body["bound_body_regions"] == 0, "Wrong byte-field body")
        flow = statements(body["body"])
        require(flow[-1] == ("Return", None), "Expected a byte-field return")
        env = {1: ("x", 8)}
        computation = self.emit_flow(flow[:-1], env)
        return "\n".join([f"def {lean} (x : BitVec 8) : BitVec 8 :=", *computation, f"  {env[0][0]}"])

    def emit_flow(self, flow, env):
        emitted = []
        for index, (kind, statement) in enumerate(flow):
            if kind == "Assign":
                destination, raw = statement
                result = self.rvalue(env, raw)
            else:
                require(kind == "Call", "Unsupported byte-field statement")
                destination, result = self.call(env, statement)
            require(self.width(destination["ty"]) == result[1], "Wrong byte-field assignment width")
            name = f"_v{index}"
            emitted.append(f"  let {name} := {result[0]}")
            env[destination["kind"]["Local"]] = (name, result[1])
        return emitted

    def mix_column(self):
        body = self.local("mix_column")["body"]["Structured"]
        require(body["locals"]["arg_count"] == 1, "Unexpected MixColumns arity")
        flow = iter(statements(body["body"]))

        def take(expect):
            actual, args = next(flow)
            require(actual == expect, f"Expected MixColumns {expect}")
            return args

        def projected(place, local):
            base, field = place["kind"]["Projection"]
            require(base["kind"] == {"Local": local} and field == "Deref", "Wrong MixColumns reference")

        def unit(args):
            destination, raw = args
            constructor, operands = raw["Aggregate"]
            decl, variant, union = constructor["Adt"]
            require(destination["kind"] == {"Local": 0} and not operands and variant is union is None
                    and decl["builtin"] == "Tuple", "Expected MixColumns unit return")

        unit(take("Assign"))
        projected(take("PlaceMention"), 1)
        env = {}
        for _ in range(4):
            destination, raw = take("Assign")
            borrow = raw["Ref"]
            projected(borrow["place"], 1)
            require(borrow["kind"] == "Shared" and "Const" in borrow["ptr_metadata"], "Wrong column borrow")
            item = take("Call")
            call = item["call"]
            pointer = call["func"]["Regular"]
            name = path(self.functions[pointer["kind"]["Fun"]])
            array, index = call["args"]
            (size,) = pointer["generics"]["const_generics"]
            index_ty, index_value = self.number(index)
            require(name[:2] == [ident("core"), ident("array")] and name[-1] == ident("index")
                    and array["Move"]["kind"] == destination["kind"]
                    and self.number({"Const": size}) == ("Usize", 4)
                    and index_ty == "Usize" and 0 <= index_value < 4
                    and statements(item["on_unwind"]) == [("Abort", "UndefinedBehavior")],
                    "Expected a checked read from the four-byte column")
            byte, source = take("Assign")
            value, initialized = source["Use"]
            projected(value["Copy"], call["dest"]["kind"]["Local"])
            require(initialized == "Yes" and self.width(byte["ty"]) == 8, "Expected MixColumns input byte")
            env[byte["kind"]["Local"]] = ("abcd"[index_value], 8)
        *arithmetic, assignment, return_unit, ret = list(flow)
        emitted = self.emit_flow(arithmetic, env)
        require(assignment[0] == "Assign" and return_unit[0] == "Assign" and ret == ("Return", None),
                "Expected one final MixColumns write")
        unit(return_unit[1])
        destination, raw = assignment[1]
        projected(destination, 1)
        aggregate, values = raw["Aggregate"]
        byte, size, _ = aggregate["Array"]
        require(self.width(byte) == 8 and self.number({"Const": size}) == ("Usize", 4) and len(values) == 4,
                "Expected a four-byte MixColumns result")
        words = [self.value(env, item) for item in values]
        require(all(width == 8 for _, width in words), "Wrong MixColumns result widths")
        result = ", ".join(code for code, _ in words)
        return "\n".join(["def mixColumn (a b c d : BitVec 8) : BitVec 8 × BitVec 8 × BitVec 8 × BitVec 8 :=",
                          *emitted, f"  ({result})"])


def meaningful_cleanup(item):
    return statements(item["on_unwind"]) == [("UnwindResume", None)]


def translate(input_):
    reader = ByteOperations(input_)
    objects = [reader.emit("mul_x", "mulX"), reader.emit("square", "square"), reader.mix_column()]
    return "import Std\n\nnamespace Abc.Extracted.Aes256\n\n" + "\n\n".join(objects) + "\n\nend Abc.Extracted.Aes256\n"
