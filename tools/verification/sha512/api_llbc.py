"""Lower the structured SHA-512 public wrapper, encoder and accepted update."""

from stream_llbc import Interpret, Ref, Scalar, Terms, body, ident, lean_stream_module, operations, require


OK = ("ok", "unit")
ERR = ("err", "message-too-long")


class Api(Interpret):
    def place(self, node):
        match node["kind"]:
            case {"Global": {"id": index}} if ident(self.terms.crate["global_decls"][index]) == (
                "abc_sha512", "INITIAL_STATE",
            ):
                return "initial-registers"
            case {"Projection": [inner, {"Field": [variant, index]}]}:
                value = self.place(inner)
                if value == "context":
                    return super().place(node)
                require(isinstance(value, tuple) and len(value) > 0, "Invalid API field projection")
                match value[0], variant, index:
                    case "chunks", None, 0 | 1:
                        return value[index + 1]
                    case "update-result", 0, 0:
                        return "unit"
                    case "update-result", 1, 0:
                        return "update-error"
                    case "item", 1, 0:
                        return value[1]
                    case "pair", None, 0 | 1:
                        return value[index + 1]
                    case _:
                        raise ValueError(f"Unexpected API field projection {value[0], variant, index}")
            case _:
                return super().place(node)

    def aggregate(self, descriptor, values):
        match descriptor:
            case {"Adt": [{"id": index}, variant, None]}:
                name = ident(self.terms.crate["type_decls"][index])
                match name, variant, values:
                    case ("abc_sha512", "Sha512"), None, ["initial-registers", storage, buffered, prior]:
                        return ("new-context", storage, buffered, prior)
                    case ("core", "ops", "range", "Range"), None, [Scalar("Usize") as start, Scalar("Usize") as end]:
                        return ("range", start, end)
                    case ("core", "ops", "range", "RangeTo"), None, [Scalar("Usize") as end]:
                        return ("range", Scalar.constant("Usize", 0), end)
                    case ("core", "ops", "range", "RangeFrom"), None, [Scalar("Usize") as start]:
                        return ("from", start)
                    case ("abc_sha512", "MessageTooLong"), None, []:
                        return "message-too-long"
                    case ("core", "result", "Result"), 0, [value]:
                        return ("ok", value)
                    case ("core", "result", "Result"), 1, [value]:
                        return ("err", value)
                if name == () and variant is None and not values:
                    return "unit"
        raise ValueError(f"Unsupported SHA-512 API aggregate {descriptor} with {values}")

    def binary(self, operation, lhs, rhs):
        if operation in ("Ne", "Eq", "Lt", "Le"):
            require(isinstance(lhs, Scalar) and isinstance(rhs, Scalar) and lhs.kind == rhs.kind,
                    "Unexpected SHA-512 comparison operands")
            operator = {"Ne": "≠", "Eq": "=", "Lt": "<", "Le": "≤"}[operation]
            return Scalar("Prop", f"({lhs.lean} {operator} {rhs.lean})")
        return super().binary(operation, lhs, rhs)

    def assign(self, place, value):
        if "Local" in place["kind"]:
            super().assign(place, value)
            return
        match self.place(place), value:
            case Scalar("Usize", "buffered"), Scalar("Usize") as stored:
                self.effects.append(("buffered", stored))
            case "destination-chunk", ("encoded-word", order):
                self.effects.append(("store-word", order))
            case _:
                super().assign(place, value)

    def width(self, call):
        [width] = call["func"]["Regular"]["generics"]["const_generics"]
        scalar = self.terms.constant(width)
        require(isinstance(scalar, Scalar) and scalar.kind == "Usize" and scalar.number > 0,
                "Expected a positive Rust const-generic chunk width")
        return scalar.number

    def call(self, call):
        name = self.terms.function_name(call)
        args = [self.operand(arg) for arg in call["args"]]
        value = None
        match name, args:
            case ("core", "array", "repeat"), [Scalar("U8") as byte]:
                value = ("repeat", self.width(call), byte)
            case ("core", "array", "as_mut_slice"), [Ref(("repeat", _, _) as array)]:
                value = Ref(array)
            case ("core", "slice", "as_chunks_mut"), [Ref(("repeat", _, _) as array)]:
                width = self.width(call)
                value = ("chunks", Ref(("destination-chunks", array, width)), "destination-remainder")
            case ("core", "slice", "iter_mut"), [Ref(("destination-chunks", _, _) as chunks)]:
                value = ("output-iter", chunks)
            case ("core", "iter", "traits", "iterator", "Iterator", "zip"), [("output-iter", _) as out, "state"]:
                value = ("zip-iter", out)
            case ("core", "iter", "traits", "collect", "into_iter"), [("zip-iter", _) as iterator]:
                value = iterator
            case ("core", "iter", "adapters", "zip", "next"), [Ref(("zip-iter", _) as it)]:
                self.effects.append(("next", it))
                value = ("item", ("pair", Ref("destination-chunk"), "state-word"))
            case ("core", "num", "to_be_bytes" | "to_le_bytes"), ["state-word"]:
                [word] = self.terms.crate["fun_decls"][call["func"]["Regular"]["kind"]["Fun"]]["signature"]["inputs"]
                require(self.terms.types[scalar_index(word)] == "U64", "Expected a Rust u64 serialization operation")
                value = ("encoded-word", name[-1])
            case ("abc_sha512", "new"), []:
                self.effects.append(("new",))
                value = "context"
            case ("abc_sha512", "update"), [Ref("context"), Ref("input")]:
                self.effects.append(("update",))
                value = "update-return"
            case ("core", "result", "branch"), ["update-return"]:
                value = ("update-result",)
            case ("core", "result", "from_residual"), ["update-error"]:
                value = ERR
            case ("abc_sha512", "finalize"), ["context"]:
                self.effects.append(("finalize",))
                value = "digest"
            case ("core", "cmp", "Ord", "min" | "max"), [Scalar("Usize") as lhs, Scalar("Usize") as rhs]:
                value = Scalar("Usize", f"({name[-1]} {lhs.lean} {rhs.lean})")
            case ("core", "slice", "len"), [Ref(("remainder", _, _))]:
                value = Scalar("Usize", "tail.length")
            case ("core", "array", "index_mut"), [Ref("block"), ("range", _, _) as region]:
                value = Ref(region)
            case ("core", "slice", "index", "index"), [Ref("input"), ("range", _, _) as region]:
                value = Ref(("input-prefix", region))
            case ("core", "slice", "index", "index"), [Ref("input"), ("from", _) as region]:
                value = Ref(("remaining-input", region))
            case ("core", "slice", "copy_from_slice"), [Ref(("range", _, _) as region), Ref(source)]:
                self.effects.append(("copy-window", region, source))
            case ("core", "slice", "as_chunks"), [Ref(source)]:
                require(source == "input" or source[0] == "remaining-input", "Unexpected as_chunks input")
                width = self.width(call)
                value = ("chunks", Ref(("full-chunks", source, width)), Ref(("remainder", source, width)))
            case ("core", "slice", "iter", "into_iter"), [Ref(("full-chunks", _, _) as chunks)]:
                value = ("chunks-iter", chunks)
            case ("core", "slice", "iter", "next"), [Ref(("chunks-iter", _) as iterator)]:
                self.effects.append(("next", iterator))
                value = ("item", Ref("current-chunk"))
            case ("abc_sha512", "compress"), [Ref("state"), Ref("current-chunk")]:
                self.effects.append(("compress-current",))
            case _:
                return super().call(call)
        self.assign(call["dest"], value)

    def statements(self, code):
        for node in code:
            if isinstance(node, dict) and "Drop" in node:
                # The recognized zip holds a slice iterator and an array iterator over u64 words.
                dropped = self.place(node["Drop"]["place"])
                require(isinstance(dropped, tuple) and dropped[0] == "zip-iter", "Unexpected SHA-512 drop")
            else:
                super().statements([node])

    def variant_branches(self, switch, value, type_name):
        data = switch["data"]
        require(self.place(data["scrutinee"]["Discriminant"]) == value and data["fallback"] is None,
                "Unexpected SHA-512 enum scrutinee")
        arms = {}
        for tag, index in data["branches"]:
            match self.terms.raw_constant(tag):
                case {"Discriminant": [{"id": type_id}, variant]}:
                    require(ident(self.terms.crate["type_decls"][type_id]) == type_name,
                            "Unexpected SHA-512 enum type")
                    arms[variant] = index
                case _:
                    raise ValueError("Expected a SHA-512 enum discriminant")
        require(set(arms) == {0, 1} and sorted(arms.values()) == [0, 1] and len(switch["branches"]) == 2,
                "Expected an exhaustive two-arm SHA-512 enum switch")
        return tuple(operations(switch["branches"][arms[n]]) for n in (0, 1))


def scalar_index(node):
    match node:
        case {"Value": [index, _]} | {"Deduplicated": index}:
            return index
        case _:
            raise ValueError("Unexpected SHA-512 scalar type encoding")


def function_code(terms, name):
    return operations(body(terms.declaration("fun_decls", ("abc_sha512", name))))


def initial_state(terms):
    model = Api(terms, {})
    *code, result = function_code(terms, "new")
    require(result == "Return", "Unexpected SHA-512 constructor return")
    model.statements(code)
    require(not model.effects, "Unexpected SHA-512 constructor effect")
    match model.values[0]:
        case ("new-context", ("repeat", width, Scalar("U8") as byte), Scalar("Usize") as buffered,
              Scalar("U128") as prior):
            pass
        case _:
            raise ValueError("Unexpected SHA-512 constructor values")
    declaration = terms.declaration("global_decls", ("abc_sha512", "INITIAL_STATE"))
    match terms.raw_constant(declaration["value"]):
        case {"Call": [{"kind": {"Fun": initializer}}, []]}:
            match operations(body(terms.crate["fun_decls"][initializer])):
                case [{"Assign": [{"kind": {"Local": 0}}, {"Aggregate": [{"Array": _}, operands]}]}, "Return"]:
                    initial = [model.operand(operand) for operand in operands]
                case _:
                    raise ValueError("Expected a SHA-512 initializer that returns an array literal")
        case _:
            raise ValueError("Expected a SHA-512 initializer body")
    require(len(initial) == 8 and all(isinstance(word, Scalar) and word.kind == "U64" for word in initial),
            "Expected eight initial SHA-512 words")
    return initial, width, byte, buffered, prior


def loop_iteration(model, loop):
    code = operations(loop)
    switch_at = next(i for i, node in enumerate(code) if "Switch" in node)
    model.statements(code[:switch_at])
    switch = code[switch_at]["Switch"]
    item = model.place(switch["data"]["scrutinee"]["Discriminant"])
    require(item[0] == "item", "The SHA-512 loop did not dispatch on its iterator item")
    missing, present = model.variant_branches(switch, item, ("core", "option", "Option"))
    require(missing == [{"Break": 0}] and not present and code[-1] == {"Continue": 0},
            "Unexpected SHA-512 iterator control flow")
    model.statements(code[switch_at + 1:-1])


def serialize(terms):
    code = function_code(terms, "finalize")
    calls = [i for i, node in enumerate(code) if isinstance(node, dict) and "Call" in node and
             terms.function_name(node["Call"]["call"]) == ("abc_sha512", "compress")]
    require(len(calls) == 1, "Unexpected number of SHA-512 finalizer tail compressions")
    code = code[calls[0] + 1:]
    loop_at = next(i for i, node in enumerate(code) if "Loop" in node)
    model = Api(terms, {1: "context"})
    model.statements(code[:loop_at])
    loop_iteration(model, code[loop_at]["Loop"])
    require(code[-1] == "Return", "SHA-512 finalizer does not return after serializing")
    model.statements(code[loop_at + 1:-1])
    match model.effects:
        case [("next", ("zip-iter", ("output-iter", ("destination-chunks", array, width)))), ("store-word", order)]:
            require(model.values[0] == array, "SHA-512 finalizer returned a different buffer")
            _, size, marker = array
            require(width == 8 and size == 64, "SHA-512 output must contain eight consecutive eight-byte chunks")
            return order, marker
        case _:
            raise ValueError("Unexpected SHA-512 serialization effects")


def public_wrapper(terms):
    *code, result = function_code(terms, "digest")
    require(result == "Return", "Unexpected SHA-512 public wrapper return")
    branch = next(i for i, node in enumerate(code) if "Switch" in node)
    model = Api(terms, {1: Ref("input")})
    model.statements(code[:branch])
    require(model.effects == [("new",), ("update",)], "The SHA-512 wrapper must update the newly constructed context")
    success, failure = model.variant_branches(code[branch]["Switch"], ("update-result",),
                                             ("core", "ops", "control_flow", "ControlFlow"))
    require(not success and failure[-1] == "Return", "Unexpected SHA-512 wrapper result branches")
    rejected = Api(terms, model.values)
    rejected.statements(failure[:-1])
    require(not rejected.effects and rejected.values[0] == ERR, "The SHA-512 wrapper must return the original error")
    model.effects.clear()
    model.statements(code[branch + 1:])
    require(model.effects == [("finalize",)] and model.values[0] == ("ok", "digest"),
            "The SHA-512 wrapper must return the finalized updated context")


def check_chunk_driver(model, code, source):
    loop_at = next(i for i, node in enumerate(code) if "Loop" in node)
    model.statements(code[:loop_at])
    loop_iteration(model, code[loop_at]["Loop"])
    require(code[-1] == "Return", "The SHA-512 chunk driver must return after storing the tail")
    model.statements(code[loop_at + 1:-1])
    tail_size = Scalar("Usize", "tail.length")
    require(model.effects == [
        ("next", ("chunks-iter", ("full-chunks", source, 128))),
        ("compress-current",),
        ("copy-window", ("range", Scalar.constant("Usize", 0), tail_size), ("remainder", source, 128)),
        ("buffered", tail_size),
    ] and model.values[0] == OK, "Unexpected SHA-512 full-block or trailing-byte effects")


def accepted_update(terms):
    *code, result = function_code(terms, "update")
    model = Api(terms, {1: Ref("context"), 2: Ref("input")})
    gate_at = next(i for i, node in enumerate(code) if "Switch" in node)
    require(gate_at == len(code) - 1 and result == "Return", "Unexpected SHA-512 update length branch")
    model.statements(code[:gate_at])
    require(not model.effects, "The SHA-512 update writes before checking the length")
    _, rejected, admitted = model.split(code[gate_at]["Switch"])
    failure = Api(terms, model.values)
    failure.statements(rejected)
    require(not failure.effects and failure.values[0] == ERR, "Invalid SHA-512 update rejection")
    prefix_at = next(i for i, node in enumerate(admitted) if "Switch" in node)
    require(prefix_at == len(admitted) - 1, "Unexpected code after the SHA-512 update prefix branch")
    model.statements(admitted[:prefix_at])
    require(len(model.effects) == 1 and model.effects[0][0] == "counter", "Invalid SHA-512 counter update")
    has_pending, fill, direct = model.split(admitted[prefix_at]["Switch"])
    check_chunk_driver(Api(terms, model.values), direct, "input")

    stop_at = next(i for i, node in enumerate(fill) if "Switch" in node)
    prefix = Api(terms, model.values)
    prefix.statements(fill[:stop_at])
    match prefix.effects:
        case [("copy-window", ("range", Scalar("Usize", "buffered"), end),
               ("input-prefix", ("range", Scalar("Usize", "0"), copied))), ("buffered", stored)] if stored == end:
            pass
        case _:
            raise ValueError("Unexpected SHA-512 prefix-copy effects")
    stop, short, full = prefix.split(fill[stop_at]["Switch"])
    require(full[-1] == "Return" and not short, "Unexpected SHA-512 prefix completion branch")
    prefix.effects.clear()
    prefix.statements(fill[stop_at + 1:])
    require(not prefix.effects and prefix.values[0] == OK, "The short SHA-512 prefix must return immediately")

    tail_at = next(i for i, node in enumerate(full) if "Call" in node and
                   terms.function_name(node["Call"]["call"]) == ("core", "slice", "as_chunks"))
    complete = Api(terms, prefix.values)
    complete.statements(full[:tail_at])
    require(complete.effects == [("compress",)], "The completed SHA-512 buffer must be compressed before full chunks")
    complete.effects.clear()
    check_chunk_driver(complete, full[tail_at:], ("remaining-input", ("from", copied)))
    return has_pending, copied, end, stop


def lean_api_module(artifact, target):
    stream = lean_stream_module(artifact, target)
    terms = Terms(artifact["translated"])
    initial, block_size, initial_byte, initial_buffered, initial_prior = initial_state(terms)
    order, _ = serialize(terms)
    public_wrapper(terms)
    has_pending, copied, end, stop = accepted_update(terms)
    initial_words = ", ".join(word.lean for word in initial)
    encoded = "Abc.Foundation.bytesBigEndian 8 word.toNat"
    if order == "to_le_bytes":
        encoded += " |>.reverse"
    return stream, f"""import Sha512StreamSourceRefinement
import Sha512LlbcRefinement

namespace Abc.Refine.Sha512.ApiSource

open Abc.Spec.Sha512 (Byte Message)
open Abc.Refine.Sha512.Streaming
open Abc.Refine.Sha512.StreamSource

def sourceInitialRegisters : Registers := ⟨{initial_words}⟩
def sourceInitialStorage : Message := List.replicate {block_size} {initial_byte.lean}
def sourceInitialBuffered : Nat := {initial_buffered.lean}
def sourceInitialPrior : Nat := {initial_prior.lean}

def sourceEncodeWord (word : UInt64) : Message := {encoded}
def sourceEncode (r : Registers) : Message :=
  [r.a, r.b, r.c, r.d, r.e, r.f, r.g, r.h].flatMap sourceEncodeWord

def sourceHasPending (buffered : Nat) : Prop := {has_pending.lean}
instance (buffered : Nat) : Decidable (sourceHasPending buffered) :=
  inferInstanceAs (Decidable {has_pending.lean})
def sourceCopied (incoming buffered : Nat) : Nat := {copied.lean}
def sourceEnd (incoming buffered : Nat) : Nat := {end.lean}
def sourceStops (incoming buffered : Nat) : Prop := {stop.lean}
instance (incoming buffered : Nat) : Decidable (sourceStops incoming buffered) :=
  inferInstanceAs (Decidable {stop.lean})

structure StorageUpdate where
  emitted : List Message
  storage : Message
  buffered : Nat

def sourceChunkTail (written : Message) (complete : List Message) (remaining : Message) : StorageUpdate :=
  let (blocks, tail) := splitBlocks remaining
  ⟨complete ++ blocks, overwriteWindow written 0 tail, tail.length⟩

def sourceDriver (storage : Message) (buffered : Nat) (input : Message) : StorageUpdate :=
  if sourceHasPending buffered then
    let copied := sourceCopied input.length buffered
    let written := overwriteWindow storage buffered (input.take copied)
    if sourceStops input.length buffered then
      ⟨[], written, sourceEnd input.length buffered⟩
    else sourceChunkTail written [written] (input.drop copied)
  else sourceChunkTail storage [] input

/-- The constructor, update, `Result` branch, and finalizer in public `digest`. -/
def sourceDigestUsing (compress : Registers → Message → Registers) (message : Message) : Option Message :=
  if sourceRejects sourceInitialPrior message.length then none
  else
    let next := sourceDriver sourceInitialStorage sourceInitialBuffered message
    let chained := next.emitted.foldl compress sourceInitialRegisters
    let final := emittedBlocks next.storage next.buffered (sourceCount sourceInitialPrior message.length)
    some (sourceEncode (final.foldl compress chained))

def sourceDigest (message : Message) : Option Message :=
  sourceDigestUsing Llbc.generatedCompression message

end Abc.Refine.Sha512.ApiSource
"""
