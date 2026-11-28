"""Translate the supported, effect-free Charon LLBC subset for GHASH words."""

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


def meaningful(block):
    ignored = {"StorageLive", "StorageDead", "Borrowck"}
    return [(tag, value) for tag, value in (tagged(stmt["kind"]) for stmt in block["statements"])
            if tag not in ignored]


def local_operand(operand):
    tag, place = tagged(operand)
    require(tag in ("Copy", "Move"), "Expected a local move or copy")
    return place["kind"]["Local"]


@dataclass(frozen=True)
class Expression:
    code: str
    ty: int | str


class ScalarLoop:
    # Functions are emitted in dependency order. The loop is emitted separately.
    CUTPOINTS = {
        "hash_block": ([128, 128, 128], ["multiply"]),
        "pack_lengths": ([64, 64], []),
        "finish_tag": ([128, 128, 128, 128], ["hash_block"]),
    }

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
        self.type_declarations = {entry["def_id"]: entry for entry in crate["type_decls"] if entry is not None}
        self.globals = {entry["def_id"]: entry for entry in crate["global_decls"] if entry is not None}
        (target,) = crate["target_information"]
        self.pointer_bits = 8 * target["value"]["target_pointer_size"]
        require(self.pointer_bits in (32, 64), "Unsupported pointer width")
        self.load("multiply", [128, 128])
        named = {local["name"]: local["index"] for local in self.body["locals"]["locals"]
                 if local["name"] is not None}
        require(named.get("input") == 1 and named.get("key") == 2, "Unexpected input locals")
        self.product, self.bit = named["product"], named["bit"]
        require([self.locals[k] for k in (0, 1, 2, self.product, self.bit)] == [128, 128, 128, 128, 32],
                "Unexpected live GHASH state types")

    def local_function(self, name):
        path = [ident("abc_aes256_gcm"), ident(name)]
        matches = [entry for entry in self.functions.values() if name_segments(entry) == path]
        require(len(matches) == 1 and matches[0]["item_meta"]["is_local"] is True,
                f"Expected one local {name} function")
        return matches[0]

    def load(self, name, widths, output=128):
        source = self.local_function(name)
        self.signature(source, widths, output)
        self.body = source["body"]["Structured"]
        require(self.body["bound_body_regions"] == 0 and self.body["locals"]["arg_count"] == len(widths),
                "Unexpected function body arguments")
        locals_ = self.body["locals"]["locals"]
        self.locals = {local["index"]: self.scalar_type(local["ty"]) for local in locals_}
        require([self.locals[k] for k in range(1 + len(widths))] == [output, *widths],
                "Function argument locals do not match the signature")

    def collect_definitions(self, term):
        if isinstance(term, dict):
            if "Value" in term and isinstance(term["Value"], list) and len(term["Value"]) == 2:
                index, value = term["Value"]
                if isinstance(value, dict) and set(value) == {"Scalar"}:
                    require(index not in self.types or self.types[index] == value, "Conflicting LLBC scalar types")
                    self.types[index] = value
                if (isinstance(value, list) and len(value) == 2 and isinstance(value[0], dict)
                        and set(value[0]) in ({"Integer"}, {"Bool"}, {"Discriminant"})):
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
        if width == "Usize":
            return self.pointer_bits
        require(width in ("U128", "U64", "U32", "U8"), f"Unsupported LLBC scalar type {scalar}")
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
        value, reference_type = self.constant_data(reference)
        ty = self.scalar_type(reference_type)
        if ty == "Bool":
            require(type(value["Bool"]) is bool, "Unexpected Boolean literal")
            return Expression(str(value["Bool"]).lower(), ty)
        integer, digits = value["Integer"]["Unsigned"]
        number = int(digits)
        require((integer == f"U{ty}" or integer == "Usize" and ty == self.pointer_bits)
                and 0 <= number < 2**ty, "Unexpected integer literal")
        return Expression(f"{number}#{ty}", ty)

    def constant_data(self, reference):
        tag, data = tagged(reference)
        require(tag in ("Value", "Deduplicated"), f"Unsupported constant reference: {tag}")
        return data[1] if tag == "Value" else self.constants[data]

    def operand(self, env, operand):
        tag, data = tagged(operand)
        if tag == "Const":
            return self.constant(data)
        require(tag in ("Copy", "Move"), f"Unsupported LLBC operand: {tag}")
        place_kind, place = tagged(data["kind"])
        if place_kind == "Global":
            decl = self.globals[place["id"]]
            require(tag == "Copy" and decl["global_kind"] == "NamedConst"
                    and not any(decl["generics"].values()) and not any(place["generics"].values()),
                    "Expected an immutable evaluated constant")
            value = self.constant(decl["value"])
            require(value.ty == self.scalar_type(decl["ty"]) == self.scalar_type(data["ty"]),
                    "Mismatched global scalar type")
            return value
        index = self.local_index(data)
        require(index in env, f"Use of local {index} outside its translated scope")
        return env[index]

    def arithmetic(self, env, value, checks):
        tag, data = tagged(value)
        if tag == "Use":
            require(data[1] == "Yes", "Unexpected non-initializing assignment")
            return self.operand(env, data[0])
        if tag == "UnaryOp":
            cast, operand = data
            source, destination = (item["Integer"]["Unsigned"] for item in cast["Cast"]["Scalar"])
            value = self.operand(env, operand)
            if (source, destination) == ("U64", "U128"):
                require(value.ty == 64, "Unexpected widening operand")
                return Expression(f"({value.code}.zeroExtend 128)", 128)
            require((source, destination) == ("Usize", "U32") and value.ty == self.pointer_bits,
                    "Unsupported integer cast")
            return Expression(f"({value.code}).setWidth 32", 32)
        require(tag == "BinaryOp", f"Unsupported LLBC expression: {tag}")
        operator, lhs, rhs = data
        op, overflow = tagged(operator)
        left, right = self.operand(env, lhs), self.operand(env, rhs)
        lval, rval = left.code, right.code
        if op in ("Shr", "Shl"):
            require(overflow == "Panic" and left.ty == 128 and right.ty == 32, "Unexpected shift")
            checks.append(f"({rval}).toNat < 128")
            symbol = ">>>" if op == "Shr" else "<<<"
            return Expression(f"({lval} {symbol} ({rval}).toNat)", 128)
        require(left.ty == right.ty and left.ty in (32, 64, 128), "Binary operand type mismatch")
        if op in ("Gt", "Ge", "Lt", "Le"):
            require(overflow is None, "Unexpected checked comparison")
            rel = {"Gt": ">", "Ge": "≥", "Lt": "<", "Le": "≤"}[op]
            return Expression(f"(decide (({lval}).toNat {rel} ({rval}).toNat))", "Bool")
        if op == "Sub":
            require(overflow == "Panic" and left.ty == 32, "Unexpected checked subtraction")
            checks.append(f"({rval}).toNat ≤ ({lval}).toNat")
            return Expression(f"({lval} - {rval})", 32)
        if op == "Add":
            require(overflow == "Panic" and left.ty == 32, "Unexpected checked addition")
            checks.append(f"({lval}).toNat + ({rval}).toNat < 2^32")
            return Expression(f"({lval} + {rval})", 32)
        if op == "Mul":
            require(overflow == "Panic" and left.ty == 128, "Unexpected checked multiplication")
            checks.append(f"({lval}).toNat * ({rval}).toNat < 2^128")
            return Expression(f"({lval} * {rval})", 128)
        symbol = {"Eq": "==", "Ne": "!=", "BitAnd": "&&&", "BitXor": "^^^", "BitOr": "|||"}.get(op)
        require(overflow is None and symbol is not None, f"Unsupported LLBC operator: {op}")
        return Expression(f"({lval} {symbol} {rval})", "Bool" if op in ("Eq", "Ne") else left.ty)

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
        self.verify_cleanup(item)
        return self.local_index(call["dest"]), Expression(f"({args[0].code} - {args[1].code})", 128)

    def verify_cleanup(self, item):
        require(self.statements(item["on_unwind"]) == [("UnwindResume", None)],
                "Unexpected cleanup in scalar call")

    def aggregate(self, args, read):
        constructor, operands = args
        decl, variant, union = constructor["Adt"]
        require(union is None, "Unsupported aggregate")
        if decl["builtin"] == "Tuple" and variant is None and not operands:
            return ("unit",)
        path, constructor = self.enum_variant(decl, variant)
        require(len(constructor["fields"]) == len(operands), "Wrong enum variant arity")
        return path, constructor["name"], tuple(read(operand) for operand in operands)

    def enum_variant(self, decl, variant):
        definition = self.type_declarations[decl["id"]]
        path = tuple(seg["Ident"][0] for seg in name_segments(definition))
        return path, definition["kind"]["Enum"][variant]

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

    def execute(self, env, statements, on_call=None):
        env = dict(env)
        checks = []
        handler = on_call or self.wrapping_sub
        for tag, args in statements:
            if tag == "Assign":
                index, value = self.local_index(args[0]), self.arithmetic(env, args[1], checks)
            elif tag == "Call":
                index, value = handler(env, args)
            else:
                raise ValueError(f"Unsupported statement inside scalar block: {tag}")
            require(value.ty == self.locals[index], "Assignment type mismatch")
            env[index] = value
        return env, checks

    def wrapper_links(self):
        # Confirm the extracted scalar functions are reached from the tag path.
        prefix = ident("abc_aes256_gcm")

        def local_calls(node):
            if isinstance(node, dict):
                if set(node) == {"Call"}:
                    target = node["Call"]["call"]["func"].get("Regular", {}).get("kind", {}).get("Fun")
                    if target is not None:
                        path = name_segments(self.functions[target])
                        if len(path) == 2 and path[0] == prefix:
                            yield path[1]["Ident"][0]
                for value in node.values():
                    yield from local_calls(value)
            elif isinstance(node, list):
                for item in node:
                    yield from local_calls(item)

        for name, expected in {
            "authenticate": ["hash_padded", "hash_padded", "pack_lengths", "encrypt_counter", "finish_tag"],
            "hash_padded": ["hash_block", "hash_block"],
            "open_in_place": ["check_lengths", "authenticate", "tags_match", "apply_payload"],
            "seal_in_place": ["check_lengths", "apply_payload", "authenticate"],
        }.items():
            found = list(local_calls(self.local_function(name)["body"]))
            require(found == expected, f"Unexpected local call sequence in {name}: {found}")

    def comparison(self):
        self.load("tags_match", [128, 128], "Bool")
        statements = self.statements(self.body["body"])
        require(statements[-1] == ("Return", None), "Expected the comparison return")
        barriers = []

        def black_box(env, item):
            call = item["call"]
            pointer = call["func"]["Regular"]
            fn = self.functions[pointer["kind"]["Fun"]]
            require(name_segments(fn) == list(map(ident, ("core", "hint", "black_box")))
                    and fn["body"] == "Opaque", "Expected core::hint::black_box")
            generics = pointer["generics"]
            require([self.scalar_type(ty) for ty in generics["types"]] == [128]
                    and not any(v for k, v in generics.items() if k != "types"),
                    "Expected core::hint::black_box specialized at u128")
            (arg,) = call["args"]
            value = self.operand(env, arg)
            require(value.ty == 128, "Wrong black_box operand type")
            self.verify_cleanup(item)
            barriers.append(value)
            # Use the standard library's specified functional identity semantics.
            return self.local_index(call["dest"]), value

        inputs = {1: Expression("_actual", 128), 2: Expression("_expected", 128)}
        ended, checks = self.execute(inputs, statements[:-1], black_box)
        require(len(barriers) == 1 and not checks, "Unexpected tag comparison control flow")
        return ended[0].code

    def length_check(self):
        check = self.local_function("check_lengths")
        sig = check["signature"]
        require(not sig["is_unsafe"] and not sig["is_variadic"] and sig["abi"] == "Rust"
                and not any(check["generics"].values())
                and [self.scalar_type(ty) for ty in sig["inputs"]] == [64, 64], "Wrong length check signature")
        body = check["body"]["Structured"]
        require(body["bound_body_regions"] == 0 and body["locals"]["arg_count"] == 2,
                "Unexpected length check arguments")
        self.locals = {local["index"]: self.scalar_type(local["ty"]) if local["index"] != 0
                       and self.is_scalar(local["ty"]) else None for local in body["locals"]["locals"]}

        def result(items):
            expected = ("core", "result", "Result")
            error = ("abc_aes256_gcm", "Error")
            locals_ = {}
            require(items[-1] == ("Return", None), "Expected a length result return")
            for tag, operands in items[:-1]:
                require(tag == "Assign", "Unexpected statement in a length return")
                place, raw_value = operands
                value = raw_value["Aggregate"]

                def read(operand):
                    kind, source = tagged(operand)
                    require(kind in ("Copy", "Move"), "Invalid length result operand")
                    return locals_[source["kind"]["Local"]]

                locals_[place["kind"]["Local"]] = self.aggregate(value, read)
            returned = locals_[0]
            if returned == (expected, "Ok", (("unit",),)):
                return ".ok ()"
            for rust, lean in [("MessageTooLong", "messageTooLong"), ("AssociatedDataTooLong", "associatedDataTooLong")]:
                if returned == (expected, "Err", ((error, rust, ()),)):
                    return f".error .{lean}"
            raise ValueError("Unexpected length check result")

        def sequence(env, items, indent):
            for index, (tag, switch) in enumerate(items):
                if tag == "Switch":
                    values, checks = self.execute(env, items[:index])
                    require(not checks, "Unexpected panic guard in length comparison")
                    data = switch["data"]
                    condition = self.operand(values, data["scrutinee"]["Value"])
                    ((value, explicit),) = data["branches"]
                    case = self.constant(value)
                    fallback = data["fallback"]
                    branches = switch["branches"]
                    require(case.ty == condition.ty == "Bool" and {explicit, fallback} == {0, 1}
                            and len(branches) == 2, "Expected two length comparison outcomes")

                    def path(number):
                        branch = self.statements(branches[number])
                        return sequence(values, branch if branch and branch[-1] == ("Return", None)
                                        else branch + items[index + 1:], indent + "  ")

                    success, failure = (explicit, fallback) if case.code == "true" else (fallback, explicit)
                    return f"{indent}if {condition.code} then\n{path(success)}\n{indent}else\n{path(failure)}"
            return indent + result(items)

        inputs = {1: Expression("aad", 64), 2: Expression("payload", 64)}
        return sequence(inputs, self.statements(body["body"]), "  ")

    def is_scalar(self, reference):
        tag, data = tagged(reference)
        return tag == "Value" and "Scalar" in data[1] or tag == "Deduplicated" and data in self.types

    def api_length_gate(self, name):
        """Check that `?` branches on the bounds of the two input slices."""
        body = self.local_function(name)["body"]["Structured"]["body"]

        def assignment(stmt, shape):
            tag, (place, operation) = stmt
            require(tag == "Assign", "Expected a length-gate assignment")
            return place["kind"]["Local"], operation[shape]

        def invocation(stmt, args):
            tag, item = stmt
            require(tag == "Call", "Expected a length-gate call")
            call = item["call"]
            require([local_operand(arg) for arg in call["args"]] == args
                    and meaningful(item["on_unwind"]) == [("UnwindResume", None)],
                    "Unexpected length gate call dataflow or cleanup")
            callee = self.functions[call["func"]["Regular"]["kind"]["Fun"]]
            return call["dest"]["kind"]["Local"], callee

        top = meaningful(body)
        payload_locals = []
        for start, source in [(0, 3), (3, 4)]:
            dst, borrow = assignment(top[start], "Ref")
            require(borrow["kind"] == "Shared", "Length gate must read a shared slice")
            for place, projection in [(borrow["place"], "Deref"),
                                      (borrow["ptr_metadata"]["Copy"], "PtrMetadata")]:
                origin, field = place["kind"]["Projection"]
                require(field == projection and origin["kind"]["Local"] == source,
                        "Length gate must read the complete API slice")
            native, length = invocation(top[start + 1], [dst])
            length_path = name_segments(length)
            require(length_path[:2] == [ident("core"), ident("slice")] and length_path[-1] == ident("len"),
                    "Expected the standard slice length")
            cast_to, (cast, value) = assignment(top[start + 2], "UnaryOp")
            require(cast == {"Cast": {"Scalar": [{"Integer": {"Unsigned": "Usize"}},
                                                  {"Integer": {"Unsigned": "U64"}}]}}
                    and local_operand(value) == native, "Expected the usize to u64 length cast")
            payload_locals.append(cast_to)
        checked, checker = invocation(top[6], payload_locals)
        require(checker is self.local_function("check_lengths"), "Wrong bounds function")
        discriminant, conversion = invocation(top[7], [checked])
        conversion_path = name_segments(conversion)
        require(conversion_path[:2] == [ident("core"), ident("result")] and conversion_path[-1] == ident("branch"),
                "Expected the Result::branch conversion")

        tag, switch = top[8]
        require(tag == "Switch", "Length validation must branch before payload work")
        data = switch["data"]
        require(data["scrutinee"]["Discriminant"]["kind"]["Local"] == discriminant and data["fallback"] is None,
                "Length gate must branch on the bounds result")
        routes = {}
        for pattern, index in data["branches"]:
            value, _ = self.constant_data(pattern)
            declaration, variant = value["Discriminant"]
            path, constructor = self.enum_variant(declaration, variant)
            require(path == ("core", "ops", "control_flow", "ControlFlow"), "Expected the ControlFlow result")
            routes[constructor["name"]] = (variant, meaningful(switch["branches"][index]))
        require(set(routes) == {"Continue", "Break"} and not routes["Continue"][1],
                "Length success must fall through")

        variant, failed = routes["Break"]
        require(len(failed) == 4 and failed[-1] == ("Return", None), "Bounds error must return directly")
        residual, (operand, initial) = assignment(failed[0], "Use")
        root, field = operand["Copy"]["kind"]["Projection"]
        require(initial == "Yes" and root["kind"]["Local"] == discriminant and field == {"Field": [variant, 0]},
                "Wrong error residual projection")
        moved, (operand, initial) = assignment(failed[1], "Use")
        require(initial == "Yes" and local_operand(operand) == residual, "Wrong error residual forwarding")
        returned, failure = invocation(failed[2], [moved])
        failure_path = name_segments(failure)
        require(returned == 0 and failure_path[:2] == [ident("core"), ident("result")]
                and failure_path[-1] == ident("from_residual"), "Expected forwarding the Result's error")

    def payload_counter(self):
        declaration = self.local_function("apply_payload")
        body = declaration["body"]["Structured"]
        require(body["locals"]["arg_count"] == 3, "Wrong payload function arity")
        self.locals = {local["index"]: self.scalar_type(local["ty"]) for local in body["locals"]["locals"]
                       if self.is_scalar(local["ty"]) and self.scalar_width_supported(local["ty"])}

        def assignment(stmt, kind):
            tag, (place, value) = stmt
            require(tag == "Assign", "Expected a payload-loop assignment")
            return place["kind"]["Local"], value[kind]

        def reference(stmt, kind, source, projection=None):
            destination, ref = assignment(stmt, "Ref")
            expected = {"Local": source}
            if projection is not None:
                parent, field = ref["place"]["kind"]["Projection"]
                require(field == projection and parent["kind"] == expected, "Unexpected payload-loop projection")
            else:
                require(ref["place"]["kind"] == expected, "Unexpected payload-loop reborrow")
            require(ref["kind"] == kind, "Unexpected payload-loop reference kind")
            return destination, ref

        def call(stmt, expected_prefix, expected_name, *, drops=()):
            tag, item = stmt
            require(tag == "Call", "Expected a payload-loop call")
            cleanup = meaningful(item["on_unwind"])
            require(cleanup[-1:] == [("UnwindResume", None)] and
                    [(kind, drop["place"]["kind"]) for kind, drop in cleanup[:-1]] ==
                    [("Drop", {"Local": which}) for which in drops], "Wrong payload-loop cleanup")
            invoked = item["call"]
            function = self.functions[invoked["func"]["Regular"]["kind"]["Fun"]]
            names = name_segments(function)
            require(names[:len(expected_prefix)] == list(map(ident, expected_prefix))
                    and names[-1] == ident(expected_name), f"Unexpected payload-loop call: {expected_name}")
            return invoked["dest"]["kind"]["Local"], invoked["args"]

        def sole_arg(operands, expected):
            require([local_operand(arg) for arg in operands] == [expected], "Wrong payload-loop input")

        top = meaningful(body["body"])
        require(len(top) == 9 and top[6][0] == "Loop" and top[-1] == ("Return", None),
                "Expected one payload-block loop")
        for position in (0, 7):
            destination, unit = assignment(top[position], "Aggregate")
            require(destination == 0 and self.aggregate(unit, local_operand) == ("unit",),
                    "Expected the payload unit result")
        retained, buffer = reference(top[1], "TwoPhaseMut", 3, "Deref")
        metadata, projection = buffer["ptr_metadata"]["Copy"]["kind"]["Projection"]
        require(metadata["kind"] == {"Local": 3} and projection == "PtrMetadata", "Expected the full input slice")
        chunked, (slice_, width) = call(top[2], ("core", "slice"), "chunks_mut")
        require(local_operand(slice_) == retained and self.operand({}, width) == Expression(f"16#{self.pointer_bits}", self.pointer_bits),
                "Expected the full slice split into 16-byte chunks")
        enumerated, args = call(top[3], ("core", "iter", "traits", "iterator", "Iterator"), "enumerate")
        sole_arg(args, chunked)
        into_iter, args = call(top[4], ("core", "iter", "traits", "collect"), "into_iter")
        sole_arg(args, enumerated)
        iter_, (operand, initial) = assignment(top[5], "Use")
        require(initial == "Yes" and local_operand(operand) == into_iter, "Expected the enumerated chunks iterator")

        loop = meaningful(top[6][1])
        borrowed, _ = reference(loop[0], "Mut", iter_)
        arg, _ = reference(loop[1], "TwoPhaseMut", borrowed, "Deref")
        next_item, args = call(loop[2], ("core", "iter", "adapters", "enumerate"), "next")
        sole_arg(args, arg)

        def some_case(statement, item):
            tag, switch = statement
            control = switch["data"]
            require(tag == "Switch" and control["fallback"] is None
                    and control["scrutinee"]["Discriminant"]["kind"] == {"Local": item},
                    "Expected the iterator item switch")
            routes = {}
            for pattern, branch in control["branches"]:
                declaration, variant = self.constant_data(pattern)[0]["Discriminant"]
                path, constructor = self.enum_variant(declaration, variant)
                require(path == ("core", "option", "Option"), "Expected the iterator's Option return")
                routes[constructor["name"]] = variant, meaningful(switch["branches"][branch])
            require(set(routes) == {"None", "Some"} and routes["None"][1] == [("Break", 0)] and not routes["Some"][1],
                    "Expected processing only an available iterator item")
            return routes["Some"][0]

        def pair_field(statement, operation, item, some, number):
            destination, (operand, initial) = assignment(statement, "Use")
            tuple_, component = operand[operation]["kind"]["Projection"]
            option, field = tuple_["kind"]["Projection"]
            require(initial == "Yes" and component == {"Field": [None, number]}
                    and option["kind"] == {"Local": item} and field == {"Field": [some, 0]},
                    "Wrong iterator pair field")
            return destination

        some = some_case(loop[3], next_item)
        index = pair_field(loop[4], "Copy", next_item, some, 0)
        chunk = pair_field(loop[5], "Move", next_item, some, 1)
        require(self.locals[index] == self.pointer_bits and chunk not in self.locals, "Wrong chunk pair types")
        aes, _ = reference(loop[6], "Shared", 1, "Deref")
        nonce, _ = reference(loop[7], "Shared", 2, "Deref")
        counter_call, = [i for i, (tag, _) in enumerate(loop[8:], 8) if tag == "Call" and
                         loop[i][1]["call"]["func"]["Regular"]["kind"]["Fun"] == self.local_function("encrypt_counter")["def_id"]]
        stream, (aes_arg, nonce_arg, counter_arg) = call(loop[counter_call], ("abc_aes256_gcm",), "encrypt_counter")
        require(local_operand(aes_arg) == aes and local_operand(nonce_arg) == nonce, "Wrong CTR block arguments")
        input_ = Expression(f"(BitVec.ofNat {self.pointer_bits} index)", self.pointer_bits)
        values, checks = self.execute({index: input_}, loop[8:counter_call])
        output = self.operand(values, counter_arg)
        require(output.ty == 32 and checks, "Expected a checked u32 payload counter")
        counter = f"if {' ∧ '.join(checks)} then some {output.code} else none"

        tail = loop[counter_call + 1:]
        require(len(tail) == 10 and tail[-1] == ("Continue", 0) and tail[6][0] == "Loop",
                "Expected the CTR byte mutation loop and a single chunk continuation")
        borrowed, ref = reference(tail[0], "TwoPhaseMut", chunk, "Deref")
        parent, length_field = ref["ptr_metadata"]["Copy"]["kind"]["Projection"]
        require(parent["kind"] == {"Local": chunk} and length_field == "PtrMetadata", "Wrong CTR chunk length")
        byte_iter, args = call(tail[1], ("core", "slice"), "iter_mut")
        sole_arg(args, borrowed)
        pad_array, (operand, initial) = assignment(tail[2], "Use")
        require(initial == "Yes" and local_operand(operand) == stream, "Expected the computed AES keystream")
        zipped, args = call(tail[3], ("core", "iter", "traits", "iterator", "Iterator"), "zip")
        require([local_operand(arg) for arg in args] == [byte_iter, pad_array], "Wrong CTR zip inputs")
        into_iter, args = call(tail[4], ("core", "iter", "traits", "collect"), "into_iter", drops=(zipped,))
        sole_arg(args, zipped)
        zip_iter, (operand, initial) = assignment(tail[5], "Use")
        require(initial == "Yes" and local_operand(operand) == into_iter, "Wrong CTR zip iterator")
        require([(tag, drop["place"]["kind"]) for tag, drop in tail[7:9]] ==
                [("Drop", {"Local": zip_iter}), ("Drop", {"Local": into_iter})], "Wrong CTR iterator disposal")

        inner = meaningful(tail[6][1])
        require(len(inner) == 9 and inner[-1] == ("Continue", 0), "Wrong CTR byte loop structure")
        borrowed, _ = reference(inner[0], "Mut", zip_iter)
        arg, _ = reference(inner[1], "TwoPhaseMut", borrowed, "Deref")
        item, args = call(inner[2], ("core", "iter", "adapters", "zip"), "next", drops=(zip_iter, into_iter))
        sole_arg(args, arg)
        some = some_case(inner[3], item)
        byte_ref = pair_field(inner[4], "Move", item, some, 0)
        pad = pair_field(inner[5], "Copy", item, some, 1)
        value, (operand, initial) = assignment(inner[6], "Use")
        require(initial == "Yes" and local_operand(operand) == pad and self.locals[value] == self.locals[pad] == 8,
                "Expected the current keystream byte")
        tag, (destination, update) = inner[7]
        operator, left, right = update["BinaryOp"]
        target, dereference = destination["kind"]["Projection"]
        require(tag == "Assign" and dereference == "Deref" and target["kind"] == {"Local": byte_ref}
                and self.scalar_type(destination["ty"]) == 8 and left == {"Copy": destination}
                and local_operand(right) == value, "Wrong CTR byte update dataflow")
        symbol = {"BitXor": "^^^", "BitOr": "|||", "BitAnd": "&&&"}.get(operator)
        require(symbol is not None, "Unsupported CTR byte operator")
        return counter, f"byte {symbol} pad"

    def scalar_width_supported(self, reference):
        tag, data = tagged(reference)
        scalar = (data[1] if tag == "Value" else self.types[data])["Scalar"]
        return scalar == "Bool" or scalar.get("Integer", {}).get("Unsigned") in ("Usize", "U8", "U32", "U64", "U128")

    def hash_padded(self):
        body = self.local_function("hash_padded")["body"]["Structured"]
        require(body["locals"]["arg_count"] == 3, "Wrong padded GHASH arity")
        top = iter(meaningful(body["body"]))

        def take(cursor, tag):
            actual, value = next(cursor)
            require(actual == tag, f"Expected GHASH {tag}, got {actual}")
            return value

        def project(place, source, field):
            parent, selected = place["kind"]["Projection"]
            require(parent["kind"] == {"Local": source} and selected == field, "Wrong GHASH projection")

        def assign(cursor, operation):
            destination, value = take(cursor, "Assign")
            return destination["kind"]["Local"], value[operation]

        def transfer(cursor, operation, source, field=None):
            destination, (value, initialized) = assign(cursor, "Use")
            require(initialized == "Yes", "Unexpected GHASH move initialization")
            if field is None:
                require(value[operation]["kind"] == {"Local": source}, "Wrong GHASH source value")
            else:
                project(value[operation], source, field)
            return destination

        def borrow(cursor, mutability, source, *, deref=False, slice_=False):
            destination, ref = assign(cursor, "Ref")
            if deref:
                project(ref["place"], source, "Deref")
            else:
                require(ref["place"]["kind"] == {"Local": source}, "Wrong GHASH reference")
            require(ref["kind"] == mutability, "Wrong GHASH borrow kind")
            if slice_:
                project(ref["ptr_metadata"]["Copy"], source, "PtrMetadata")
            else:
                require("Const" in ref["ptr_metadata"], "Expected sized GHASH storage")
            return destination

        def invoke(cursor, prefix, method, expected, *, infallible=False):
            item = take(cursor, "Call")
            call = item["call"]
            cleanup = [("Abort", "UndefinedBehavior")] if infallible else [("UnwindResume", None)]
            require(meaningful(item["on_unwind"]) == cleanup, "Unexpected GHASH cleanup")
            pointer = call["func"]["Regular"]
            name = name_segments(self.functions[pointer["kind"]["Fun"]])
            require(name[:len(prefix)] == list(map(ident, prefix)) and name[-1] == ident(method),
                    f"Expected GHASH {method}")
            if expected is not None:
                require([local_operand(arg) for arg in call["args"]] == expected, "Wrong GHASH call arguments")
            return call["dest"]["kind"]["Local"], pointer["generics"], name, call["args"]

        def width(generics):
            (size,) = generics["const_generics"]
            require(self.constant(size) == Expression(f"16#{self.pointer_bits}", self.pointer_bits),
                    "Wrong GHASH block width")

        def unit(cursor):
            destination, value = assign(cursor, "Aggregate")
            require(destination == 0 and self.aggregate(value, local_operand) == ("unit",), "Expected GHASH unit")

        def absorb(cursor, source, deref):
            key = transfer(cursor, "Copy", 1)
            incoming = transfer(cursor, "Copy", 2, "Deref")
            block = transfer(cursor, "Copy", source, "Deref" if deref else None)
            decoded, _, name, _ = invoke(cursor, ("core", "num"), "from_be_bytes", [block])
            require(self.scalar_type(name[2]["Impl"]["Ty"]["skip_binder"]) == 128, "Wrong GHASH decode width")
            result, _, _, _ = invoke(cursor, ("abc_aes256_gcm",), "hash_block", [key, incoming, decoded])
            destination, value = take(cursor, "Assign")
            project(destination, 2, "Deref")
            operand, initializing = value["Use"]
            require(initializing == "Yes" and local_operand(operand) == result, "Wrong GHASH state writeback")

        unit(top)
        input_ = borrow(top, "Shared", 3, deref=True, slice_=True)
        split, generics, _, _ = invoke(top, ("core", "slice"), "as_chunks", [input_])
        width(generics)
        require([self.scalar_type(ty) for ty in generics["types"]] == [8], "Wrong GHASH byte type")
        full = transfer(top, "Copy", split, {"Field": [None, 0]})
        tail = transfer(top, "Copy", split, {"Field": [None, 1]})
        blocks = transfer(top, "Copy", full)
        iterator, _, _, _ = invoke(top, ("core", "slice", "iter"), "into_iter", [blocks])
        live = transfer(top, "Move", iterator)
        loop = iter(meaningful(take(top, "Loop")))
        first = borrow(loop, "Mut", live)
        next_ref = borrow(loop, "TwoPhaseMut", first, deref=True)
        item, _, _, _ = invoke(loop, ("core", "slice", "iter"), "next", [next_ref])
        switch = take(loop, "Switch")
        control = switch["data"]
        require(control["scrutinee"]["Discriminant"]["kind"] == {"Local": item} and control["fallback"] is None,
                "GHASH loop must switch on the iterator result")
        routes = {}
        for pattern, branch in control["branches"]:
            decl, variant = self.constant_data(pattern)[0]["Discriminant"]
            path, value = self.enum_variant(decl, variant)
            require(path == ("core", "option", "Option"), "Wrong GHASH iteration result")
            routes[value["name"]] = variant, meaningful(switch["branches"][branch])
        require(set(routes) == {"None", "Some"} and routes["None"][1] == [("Break", 0)] and not routes["Some"][1],
                "Wrong GHASH full-block continuation")
        block = transfer(loop, "Copy", item, {"Field": [routes["Some"][0], 0]})
        absorb(loop, block, True)
        require(list(loop) == [("Continue", 0)], "Unexpected GHASH full-block operations")

        tail_ref = borrow(top, "Shared", tail, deref=True, slice_=True)
        empty, _, _, _ = invoke(top, ("core", "slice"), "is_empty", [tail_ref])
        switch = take(top, "Switch")
        control = switch["data"]
        ((case, nonempty),) = control["branches"]
        require(local_operand(control["scrutinee"]["Value"]) == empty and self.constant(case) == Expression("false", "Bool")
                and {nonempty, control["fallback"]} == {0, 1} and len(switch["branches"]) == 2
                and not meaningful(switch["branches"][control["fallback"]]), "Wrong GHASH tail guard")
        small = iter(meaningful(switch["branches"][nonempty]))
        padded, generics, _, (fill,) = invoke(small, ("core", "array"), "repeat", None, infallible=True)
        width(generics)
        fill_byte = self.operand({}, fill)
        require(fill_byte.ty == 8, "Wrong GHASH padding type")
        pad_ref = borrow(small, "Mut", padded)
        tail_ref = borrow(small, "Shared", tail, deref=True, slice_=True)
        length, _, _, _ = invoke(small, ("core", "slice"), "len", [tail_ref])
        bounds, (adt, (end,)) = assign(small, "Aggregate")
        decl, variant, union = adt["Adt"]
        require(variant is None and union is None and local_operand(end) == length
                and name_segments(self.type_declarations[decl["id"]]) == list(map(ident, ("core", "ops", "range", "RangeTo"))),
                "Wrong GHASH partial-block destination range")
        dest, generics, _, _ = invoke(small, ("core", "array"), "index_mut", [pad_ref, bounds])
        width(generics)
        dest = borrow(small, "TwoPhaseMut", dest, deref=True, slice_=True)
        tail_ref = borrow(small, "Shared", tail, deref=True, slice_=True)
        invoke(small, ("core", "slice"), "copy_from_slice", [dest, tail_ref])
        absorb(small, padded, False)
        for route in (top, small):
            unit(route)
            require(list(route) == [("Return", None)], "Wrong GHASH padded return")
        return fill_byte.code

    def counter_serialization(self):
        """Check the byte copies into the exact block consumed by the AES call."""
        function = self.local_function("encrypt_counter")
        body = function["body"]["Structured"]
        require(body["locals"]["arg_count"] == 3 and self.scalar_type(function["signature"]["inputs"][2]) == 32,
                "Wrong counter serialization signature")
        top = meaningful(body["body"])
        position = iter(top)

        def assignment(operation):
            tag, (place, value) = next(position)
            require(tag == "Assign", "Expected a counter-block assignment")
            return place["kind"]["Local"], value[operation]

        def reference(kind, source, *, deref=False, slice_=False):
            destination, ref = assignment("Ref")
            place = ref["place"]["kind"]
            if deref:
                place, projection = place["Projection"]
                require(projection == "Deref", "Wrong counter-block reborrow")
                place = place["kind"]
            require(place == {"Local": source} and ref["kind"] == kind, "Wrong counter-block reference")
            if slice_:
                origin, field = ref["ptr_metadata"]["Copy"]["kind"]["Projection"]
                require(origin["kind"] == {"Local": source} and field == "PtrMetadata",
                        "Counter-block copy must preserve slice metadata")
            else:
                require("Const" in ref["ptr_metadata"], "Expected sized counter-block storage")
            return destination

        def invoke(prefix, *methods, infallible=False):
            tag, call = next(position)
            require(tag == "Call", "Expected a counter-block call")
            cleanup = [("Abort", "UndefinedBehavior")] if infallible else [("UnwindResume", None)]
            require(meaningful(call["on_unwind"]) == cleanup, "Unexpected counter-block cleanup")
            call = call["call"]
            pointer = call["func"]["Regular"]
            declaration = self.functions[pointer["kind"]["Fun"]]
            path = name_segments(declaration)
            require(path[:len(prefix)] == list(map(ident, prefix)) and path[-1] in list(map(ident, methods)),
                    f"Wrong counter-block call: expected {methods}")
            return call["dest"]["kind"]["Local"], call["args"], pointer["generics"], path

        def array_width(generics):
            (ty,) = generics["types"]
            (width,) = generics["const_generics"]
            require(self.scalar_type(ty) == 8, "Expected a byte array")
            return self.constant(width)

        def usize(value):
            return Expression(f"{value}#{self.pointer_bits}", self.pointer_bits)

        def arguments(args, *expected):
            require([local_operand(arg) for arg in args] == list(expected), "Wrong counter-block call arguments")

        block, (zero,), generics, _ = invoke(("core", "array"), "repeat", infallible=True)
        require(self.operand({}, zero) == Expression("0#8", 8) and array_width(generics) == usize(16),
                "Expected a fresh zero AES block")

        def region(range_type):
            array = reference("Mut", block)
            bounds, (adt, (boundary,)) = assignment("Aggregate")
            decl, variant, union = adt["Adt"]
            name = name_segments(self.type_declarations[decl["id"]])
            require(variant is None and union is None
                    and name == list(map(ident, ("core", "ops", "range", range_type)))
                    and self.operand({}, boundary) == usize(12), "Wrong counter-block copy boundary")
            sliced, args, generics, _ = invoke(("core", "array"), "index_mut")
            arguments(args, array, bounds)
            require(self.constant(generics["const_generics"][0]) == usize(16), "Wrong sliced array width")
            return reference("TwoPhaseMut", sliced, deref=True, slice_=True)

        prefix = region("RangeTo")
        nonce = reference("Shared", 2, deref=True)
        bytes_, args, generics, _ = invoke(("core", "array"), "as_slice", infallible=True)
        arguments(args, nonce)
        require(array_width(generics) == usize(12), "Wrong nonce width")
        _, args, _, _ = invoke(("core", "slice"), "copy_from_slice")
        arguments(args, prefix, bytes_)

        suffix = region("RangeFrom")
        counter, (operand, initial) = assignment("Use")
        require(initial == "Yes" and local_operand(operand) == 3, "Wrong encoded counter argument")
        encoded, args, _, path = invoke(("core", "num"), "to_be_bytes", "to_le_bytes")
        method = path[-1]["Ident"][0]
        arguments(args, counter)
        require(self.scalar_type(path[2]["Impl"]["Ty"]["skip_binder"]) == 32, "Wrong counter encoder type")
        borrowed = reference("Shared", encoded)
        reborrowed = reference("Shared", borrowed, deref=True)
        bytes_, args, generics, _ = invoke(("core", "array"), "as_slice", infallible=True)
        arguments(args, reborrowed)
        require(array_width(generics) == usize(4), "Wrong encoded counter width")
        _, args, _, _ = invoke(("core", "slice"), "copy_from_slice")
        arguments(args, suffix, bytes_)

        aes = reference("Shared", 1, deref=True)
        borrowed = reference("Mut", block)
        reborrowed = reference("TwoPhaseMut", borrowed, deref=True)
        _, args, _, _ = invoke(("abc_aes256",), "encrypt")
        arguments(args, aes, reborrowed)
        result, (operand, initial) = assignment("Use")
        require(result == 0 and initial == "Yes" and local_operand(operand) == block
                and list(position) == [("Return", None)], "Wrong AES output return")
        if method == "to_be_bytes":
            return "nonce ++ counter"
        return "nonce ++ (counter.extractLsb' 0 8 ++ counter.extractLsb' 8 8 ++\n    counter.extractLsb' 16 8 ++ counter.extractLsb' 24 8)"

    def api_tail(self, name):
        """Validate the shared API dataflow and each operation's result."""
        sealing = name == "seal_in_place"
        body = self.local_function(name)["body"]["Structured"]
        arity = 4 if sealing else 5
        require(body["locals"]["arg_count"] == arity, "Wrong AES-GCM API arity")
        local_ids = {local["index"] for local in body["locals"]["locals"]}

        def local(place):
            index = place["kind"]["Local"]
            require(index in local_ids, "Unknown API local")
            return index

        def statements(block):
            for statement in block["statements"]:
                tag, args = tagged(statement["kind"])
                if tag in ("StorageLive", "StorageDead"):
                    require(args in local_ids, "Storage operation on an unknown open local")
                elif tag == "Borrowck":
                    local(args["FakeRead"])
                else:
                    yield tag, args

        def callee(item):
            return self.functions[item["call"]["func"]["Regular"]["kind"]["Fun"]]

        def lookup(env, place):
            kind, data = tagged(place["kind"])
            if kind == "Local":
                return env[local(place)]
            require(kind == "Projection" and data[1] == "Deref", "Unsupported open projection")
            reference, target = lookup(env, data[0])
            require(reference in ("Shared", "TwoPhaseMut"), "Expected an open reference")
            return target

        def read(env, operand):
            kind, place = tagged(operand)
            require(kind in ("Copy", "Move"), "Unsupported open operand")
            return lookup(env, place)

        def assign(env, item):
            destination, rvalue = item
            tag, args = tagged(rvalue)
            if tag == "Use":
                require(args[1] == "Yes", "Expected initializing open assignment")
                value = read(env, args[0])
            elif tag == "Ref":
                target = lookup(env, args["place"])
                if target in ("aad", "plaintext", "ciphertext"):
                    metadata = args["ptr_metadata"]["Copy"]["kind"]["Projection"]
                    require(metadata[1] == "PtrMetadata" and lookup(env, metadata[0])[1] == target,
                            "Expected the complete input slice")
                value = (args["kind"], target)
            elif tag == "Aggregate":
                value = self.aggregate(args, lambda operand: read(env, operand))
            else:
                raise ValueError(f"Unsupported assignment in open gate: {tag}")
            index = local(destination)
            require(index == 0 or index > arity, "Gate clobbers an API argument")
            env[index] = value

        def apply_assignments(env, items):
            for tag, args in items:
                require(tag == "Assign", "Expected a local assignment in the open gate")
                assign(env, args)

        def validate_call(env, item, expected_args):
            require([read(env, arg) for arg in item["call"]["args"]] == expected_args,
                    "Unexpected AES-GCM API argument flow")
            require(list(statements(item["on_unwind"])) == [("UnwindResume", None)],
                    "Unexpected cleanup in the open gate")
            destination = local(item["call"]["dest"])
            require(destination == 0 or destination > arity, "Call clobbers an API argument")
            return destination

        def no_unique_slice_operand(operand):
            tag, place = tagged(operand)
            require(tag in ("Copy", "Move") and place["kind"] != {"Local": 4},
                    "Unexpected mutable ciphertext capability before authentication")

        def check_read_only(items):
            # Safe Rust can pass a shared reborrow to other functions. The mutable
            # input slice itself must not be moved, reassigned or mutably reborrowed.
            for tag, args in items:
                if tag == "Assign":
                    place, rvalue = args
                    index = local(place)
                    require(index == 0 or index > arity, "API prelude clobbers an argument")
                    kind, value = tagged(rvalue)
                    if kind == "Ref":
                        require(value["kind"] == "Shared", "Open prelude takes a mutable borrow")
                    else:
                        require(kind in ("Use", "UnaryOp"), "Unsupported open prelude assignment")
                        no_unique_slice_operand(value[0] if kind == "Use" else value[1])
                elif tag == "Call":
                    call = args["call"]
                    index = local(call["dest"])
                    require(index == 0 or index > arity, "API prelude call clobbers an argument")
                    for operand in call["args"]:
                        no_unique_slice_operand(operand)
                    require(list(statements(args["on_unwind"])) == [("UnwindResume", None)],
                            "Unexpected cleanup in the open prelude")
                elif tag == "Switch":
                    for branch in args["branches"]:
                        check_read_only(statements(branch))
                else:
                    require(tag == "Return", "Unsupported open prelude statement")

        top = list(statements(body["body"]))
        auth, = [i for i, (tag, item) in enumerate(top)
                 if tag == "Call" and callee(item) is self.local_function("authenticate")]
        new_at, = [i for i, (tag, item) in enumerate(top[:auth]) if tag == "Call"
                   and name_segments(callee(item))[0] == ident("abc_aes256")
                   and name_segments(callee(item))[-1] == ident("new")]
        check_read_only(top[:new_at + 1] if sealing else top[:auth + 1])
        env = {1: ("Shared", "key"), 2: ("Shared", "nonce"), 3: ("Shared", "aad"),
               4: ("TwoPhaseMut", "plaintext" if sealing else "ciphertext")}
        if not sealing:
            env[5] = ("Shared", "tag_bytes")
        apply_assignments(env, top[new_at - 1:new_at])
        aes = validate_call(env, top[new_at][1], [("Shared", "key")])
        env[aes] = "aes"
        before_auth = top[new_at + 1:auth]
        if sealing:
            apply_at, = [i for i, (tag, _) in enumerate(before_auth) if tag == "Call"]
            apply_assignments(env, before_auth[:apply_at])
            invocation = before_auth[apply_at][1]
            require(callee(invocation) is self.local_function("apply_payload"), "Expected seal to transform plaintext")
            destination = validate_call(env, invocation,
                                        [("Shared", "aes"), ("Shared", "nonce"), ("TwoPhaseMut", "plaintext")])
            env[destination] = ("unit",)
            env[4] = ("TwoPhaseMut", "ciphertext")
            before_auth = before_auth[apply_at + 1:]
        apply_assignments(env, before_auth)
        authentication = top[auth][1]
        actual = validate_call(env, authentication, [("Shared", "aes"), ("Shared", "nonce"),
                                                     ("Shared", "aad"), ("Shared", "ciphertext")])
        env[actual] = "actual"
        leading = top[auth + 1:]
        result = ("core", "result", "Result")
        if sealing:
            encode_at, = [i for i, (tag, _) in enumerate(leading) if tag == "Call"]
            apply_assignments(env, leading[:encode_at])
            encode = leading[encode_at][1]
            encoder = name_segments(callee(encode))
            require(encoder[:2] == [ident("core"), ident("num")] and encoder[-1] == ident("to_be_bytes")
                    and self.scalar_type(encoder[2]["Impl"]["Ty"]["skip_binder"]) == 128,
                    "Expected the u128 tag's big-endian serialization")
            env[validate_call(env, encode, ["actual"])] = "encoded_tag"
            require(leading[-1] == ("Return", None), "Expected the successful seal return")
            apply_assignments(env, leading[encode_at + 1:-1])
            require(env[0] == (result, "Ok", ("encoded_tag",)), "Seal must return the computed tag")
            return None
        switch_at, = [i for i, (tag, _) in enumerate(leading) if tag == "Switch"]
        decode_at, compare_at = [i for i, (tag, _) in enumerate(leading[:switch_at]) if tag == "Call"]
        apply_assignments(env, leading[:decode_at])
        decode = leading[decode_at][1]
        decoder = name_segments(callee(decode))
        require(decoder[:2] == [ident("core"), ident("num")] and decoder[-1] == ident("from_be_bytes")
                and self.scalar_type(decoder[2]["Impl"]["Ty"]["skip_binder"]) == 128,
                "Expected standard u128::from_be_bytes in the open gate")
        env[validate_call(env, decode, ["tag_bytes"])] = "expected"
        apply_assignments(env, leading[decode_at + 1:compare_at])
        compare = leading[compare_at][1]
        require(callee(compare) is self.local_function("tags_match"), "Expected the extracted tag comparison")
        env[validate_call(env, compare, ["actual", "expected"])] = "match"
        apply_assignments(env, leading[compare_at + 1:switch_at])
        switch = leading[switch_at][1]
        data = switch["data"]
        require(read(env, data["scrutinee"]["Value"]) == "match", "Gate must use the extracted comparison result")
        ((value, explicit),) = data["branches"]
        fallback = data["fallback"]
        condition = self.constant(value)
        require(condition.ty == "Bool" and {explicit, fallback} == {0, 1} and len(switch["branches"]) == 2,
                "Expected a two-way Boolean application gate")

        error = ("abc_aes256_gcm", "Error")
        # Both branches are checked before choosing the fallthrough direction.
        accept, = [i for i, block in enumerate(switch["branches"]) if not list(statements(block))]
        reject = 1 - accept
        rejected = list(statements(switch["branches"][reject]))
        require(rejected[-1] == ("Return", None), "Authentication failure must return before decryption")
        failed_env = env.copy()
        apply_assignments(failed_env, rejected[:-1])
        require(failed_env[0] == (result, "Err", ((error, "AuthenticationFailed", ()),)),
                "Wrong authentication error return")

        tail = leading[switch_at + 1:]
        apply_at, = [i for i, (tag, _) in enumerate(tail) if tag == "Call"]
        apply_assignments(env, tail[:apply_at])
        invocation = tail[apply_at][1]
        require(callee(invocation) is self.local_function("apply_payload"), "Expected accepted-path decryption")
        destination = validate_call(env, invocation,
                                    [("Shared", "aes"), ("Shared", "nonce"), ("TwoPhaseMut", "ciphertext")])
        unit = ("unit",)
        env[destination] = unit
        require(tail[-1] == ("Return", None), "Expected the accepted-path return")
        apply_assignments(env, tail[apply_at + 1:-1])
        require(env[0] == (result, "Ok", (unit,)), "Wrong successful open return")
        return condition.code if explicit == accept else ("true" if condition.code == "false" else "false")

    def straight_line(self, name, widths, dependencies):
        self.load(name, widths)
        statements = self.statements(self.body["body"])
        require(statements[-1] == ("Return", None), f"Expected a return in {name}")
        available = {self.local_function(target)["def_id"]: target for target in dependencies}
        calls = []

        def call_local(env, item):
            call = item["call"]
            pointer = call["func"]["Regular"]
            target = available[pointer["kind"]["Fun"]]
            require(not any(pointer["generics"].values()), "Unexpected generic scalar call")
            args = [self.operand(env, arg) for arg in call["args"]]
            parameters = [128, 128] if target == "multiply" else self.CUTPOINTS[target][0]
            require([arg.ty for arg in args] == parameters, "Unexpected scalar call arguments")
            self.verify_cleanup(item)
            result = f"_call{len(calls)}"
            calls.append((target, f"  let {result} ← {target} {' '.join(arg.code for arg in args)}"))
            return self.local_index(call["dest"]), Expression(result, 128)

        env = {index: Expression(f"_arg{index}", width) for index, width in enumerate(widths, 1)}
        args = " ".join(f"({expr.code} : BitVec {expr.ty})" for expr in env.values())
        ended, checks = self.execute(env, statements[:-1], call_local)
        require([target for target, _ in calls] == dependencies, f"Unexpected scalar calls in {name}")
        require(not (calls and checks), "Mixed checked expressions and calls require ordered guards")
        lines = [f"def {name} {args} : Option (BitVec 128) :=" + (" do" if calls else "")]
        lines.extend(line for _, line in calls)
        success = f"some {ended[0].code}"
        lines.append(f"  if {' ∧ '.join(checks)} then {success} else none" if checks else f"  {success}")
        return "\n".join(lines)

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
        self.wrapper_links()
        cutpoints = "\n\n".join(self.straight_line(name, *shape) for name, shape in self.CUTPOINTS.items())
        comparison = self.comparison()
        accepted = self.api_tail("open_in_place")
        self.api_tail("seal_in_place")
        length_check = self.length_check()
        for name in ("seal_in_place", "open_in_place"):
            self.api_length_gate(name)
        counter, byte_update = self.payload_counter()
        counter_serialization = self.counter_serialization()
        ghash_fill = self.hash_padded()
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

{cutpoints}

def tags_match (_actual _expected : BitVec 128) : Bool :=
  {comparison}

inductive LengthError where
  | messageTooLong
  | associatedDataTooLong
  deriving DecidableEq, Repr

def check_lengths (aad payload : BitVec 64) : Except LengthError Unit :=
{length_check}

def payload_counter (index : Nat) : Option (BitVec 32) :=
  {counter}

def counter_block (nonce : BitVec 96) (counter : BitVec 32) : BitVec 128 :=
  {counter_serialization}

def payload_byte (byte pad : BitVec 8) : BitVec 8 :=
  {byte_update}

def hash_walk (decode : List (BitVec 8) → BitVec 128) (input : List (BitVec 8)) : List (BitVec 128) :=
  if _full : 16 ≤ input.length then
    decode (input.take 16) :: hash_walk decode (input.drop 16)
  else if input.isEmpty then []
  else [decode (input ++ List.replicate (16 - input.length) {ghash_fill})]
termination_by input.length
decreasing_by simp only [List.length_drop]; omega

-- The validator resolves both returns and the unique mutable payload call.
def open_gate {{α : Type}} (applyPayload : α → α) (ciphertext : α)
    (actual expected : BitVec 128) : Bool × α :=
  if tags_match actual expected == {accepted} then (true, applyPayload ciphertext)
  else (false, ciphertext)

-- The validated seal tail reborrows the same buffer after CTR returns.
def seal_tail {{α β γ : Type}} (applyPayload : α → Option α) (authenticate : α → Option β)
    (encode : β → γ) (plaintext : α) : Option (γ × α) := do
  let ciphertext ← applyPayload plaintext
  let tag ← authenticate ciphertext
  pure (encode tag, ciphertext)

end Abc.Extracted.Ghash
"""


def translate(llbc):
    return ScalarLoop(llbc).translate()
