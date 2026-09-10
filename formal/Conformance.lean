/-
TRACE CONFORMANCE: TypeScript transitions checked against the Boundary.lean model.

THIS IS NOT A REFINEMENT PROOF. It is a decidable checker, run by the Lean
evaluator over traces that src/ emitted while it ran (MAB_TRACE=1, see
src/trace.ts). A conforming trace means: every transition THIS RUN took is one
the model's `Step` relation permits, with the model's premises (fresh id,
request derived from the operation, grant only on allow, execute only a
prepared and unspent grant) checked event by event. It says nothing about runs
not taken, about code paths that emit no event, or about the correspondence
between the model's `policy` parameter and Cedar - the trace supplies the
decision as the oracle, so the checker verifies the STRUCTURAL premises around
it, not the decision itself. It does not establish that src/ refines Boundary.lean.

What IS mechanised here, for the first time in this repository, is the link
between concrete src/ executions and the formal transition system: the same
State shape, the same two transitions, and the same premises, evaluated over
hundreds of real events rather than over the seven hand-written vectors.

Event kinds and how each maps:
  authorize   -> Boundary.Step.authorize when allow (premises: fresh, bound);
                 when deny: no transition, and the checker requires NO grant
  execute     -> Boundary.Step.execute (premises: prepared, unused; plus the
                 executed digest equals the granted operation's digest)
  refuse      -> not a transition. The checker requires that the model AGREES
                 the step was impossible (spent / wrong digest / never issued).
                 Mediation refusals are outside the model: counted "unmodelled".
  observe     -> not a transition (the model has no observation). World check:
                 authorized effect digest = observed effect digest, after an
                 execute of that operation. Counted "world-check".
  delegate    -> no operation, outside the model. Counted "unmodelled".

Deviation from Boundary.lean, stated: the model compares Operations by VALUE
(resource, payload). The trace carries the operation's sha256 digest plus the
two fields the request is derived from. Equality of digests therefore stands
in for equality of operations; that substitution assumes the digest is
collision-free over the operations seen, which Boundary.lean's header already
lists as an implementation requirement.
-/
import Lean.Data.Json
open Lean

namespace Conformance

structure Op where
  digest : String
  resource : String
  byteLen : Nat
deriving DecidableEq, Repr

structure Request where
  resource : String
  byteLen : Nat
deriving DecidableEq, Repr

/-- Mirrors Boundary.requestOf: the request is DERIVED from the operation. -/
def requestOf (op : Op) : Request := ⟨op.resource, op.byteLen⟩

structure Grant where
  id : Nat
  op : Op
  request : Request
deriving DecidableEq, Repr

/-- Same four fields as Boundary.State. executions holds grant ids. -/
structure State where
  next : Nat := 0
  intents : List Grant := []
  spent : List Nat := []
  executions : List Nat := []
deriving Repr

inductive Event where
  | authorize (requestId : String) (allow : Bool) (denialKind : Option String)
      (grantId : Option Nat) (op : Op) (request : Request)
  | delegate (requestId : String) (allow : Bool)
  | execute (requestId : String) (grantId : Nat) (digest : String)
  | refuse (requestId : Option String) (grantId : Option Nat) (digest : Option String) (reason : String)
  | observe (requestId : String) (digest : String) (authorized observed : String) (agree : Bool)
deriving Repr

inductive Verdict where
  /-- mapped onto a model transition (or a model-justified non-transition) -/
  | conform (s : State)
  /-- not a model transition; a code-level equality the trace lets us check -/
  | worldCheck (s : State)
  /-- outside the model; recorded, no check possible -/
  | unmodelled (s : State) (why : String)
  | nonconform (why : String)

def findGrant? (s : State) (id : Nat) : Option Grant := s.intents.find? (·.id == id)

def stepCheck (s : State) : Event → Verdict
  | .authorize _ true _ (some g) op req =>
      if g ≠ s.next then
        .nonconform s!"authorize: grant id {g} is not fresh; model next = {s.next}"
      else if req ≠ requestOf op then
        .nonconform s!"authorize: Cedar request {repr req} ≠ requestOf op {repr (requestOf op)}"
      else .conform { s with next := s.next + 1, intents := ⟨g, op, req⟩ :: s.intents }
  | .authorize _ true _ none _ _ => .nonconform "authorize: allow but no grant minted"
  | .authorize _ false _ (some g) _ _ => .nonconform s!"authorize: deny yet grant {g} minted"
  | .authorize _ false _ none _ _ => .conform s
  | .delegate .. => .unmodelled s "delegate: no operation; Boundary.lean has no delegation transition"
  | .execute _ g d =>
      match findGrant? s g with
      | none => .nonconform s!"execute: grant {g} was never prepared (not in intents)"
      | some gr =>
        if gr.op.digest ≠ d then
          .nonconform s!"execute: grant {g} is bound to {gr.op.digest} but executed {d}"
        else if s.spent.contains g then
          .nonconform s!"execute: grant {g} already spent"
        else .conform { s with spent := g :: s.spent, executions := g :: s.executions }
  | .refuse _ gid d reason =>
      match reason with
      | "spent" =>
        match gid with
        | some g => if s.spent.contains g then .conform s
                    else .nonconform s!"refuse(spent): grant {g} is unspent in the model"
        | none => .nonconform "refuse(spent): no grant id recorded"
      | "grant-binding" =>
        match gid, d with
        | some g, some dg =>
          match findGrant? s g with
          | some gr => if gr.op.digest ≠ dg then .conform s
                       else .nonconform s!"refuse(grant-binding): grant {g} IS bound to {dg}"
          | none => .nonconform s!"refuse(grant-binding): grant {g} not in intents"
        | _, _ => .nonconform "refuse(grant-binding): missing grant id or digest"
      | "not-issued" =>
        match gid with
        | none => .conform s
        | some g => .nonconform s!"refuse(not-issued): grant {g} was issued in the model"
      | other => .unmodelled s s!"refuse({other}): effect mediation is not in Boundary.lean"
  | .observe _ d auth obs agree =>
      if !agree || auth ≠ obs then
        .nonconform s!"observe: authorized effect {auth} ≠ observed effect {obs}"
      else if s.intents.any (fun g => g.op.digest == d && s.spent.contains g.id) then
        .worldCheck s
      else .nonconform s!"observe: no spent grant for operation {d}"

/-- The decidable step function the trace check is built on. `none` = non-conforming. -/
def stepOk (s : State) (e : Event) : Option State :=
  match stepCheck s e with
  | .conform s' | .worldCheck s' | .unmodelled s' _ => some s'
  | .nonconform _ => none

def traceOk (events : List Event) : Bool :=
  (events.foldlM stepOk {}).isSome

-- JSON -----------------------------------------------------------------------

def optField (j : Json) (k : String) : Option Json :=
  match j.getObjVal? k with
  | .ok .null => none
  | .ok v => some v
  | .error _ => none

def optNat (j : Json) (k : String) : Except String (Option Nat) :=
  match optField j k with
  | none => pure none
  | some v => (some ·) <$> fromJson? v

def optStr (j : Json) (k : String) : Except String (Option String) :=
  match optField j k with
  | none => pure none
  | some v => (some ·) <$> fromJson? v

def parseOp (j : Json) : Except String Op := do
  pure ⟨← j.getObjValAs? String "digest", ← j.getObjValAs? String "resource", ← j.getObjValAs? Nat "byteLen"⟩

def parseRequest (j : Json) : Except String Request := do
  pure ⟨← j.getObjValAs? String "resource", ← j.getObjValAs? Nat "byteLen"⟩

/-- `none` for the header line. -/
def parseEvent (j : Json) : Except String (Option Event) := do
  let kind ← j.getObjValAs? String "kind"
  match kind with
  | "header" => pure none
  | "authorize" =>
    let decision ← j.getObjValAs? String "decision"
    pure <| some <| .authorize (← j.getObjValAs? String "requestId") (decision == "allow")
      (← optStr j "denialKind") (← optNat j "grantId")
      (← parseOp (← j.getObjVal? "op")) (← parseRequest (← j.getObjVal? "request"))
  | "delegate" =>
    let decision ← j.getObjValAs? String "decision"
    pure <| some <| .delegate (← j.getObjValAs? String "requestId") (decision == "allow")
  | "execute" =>
    pure <| some <| .execute (← j.getObjValAs? String "requestId") (← j.getObjValAs? Nat "grantId")
      (← j.getObjValAs? String "executedOpDigest")
  | "refuse" =>
    pure <| some <| .refuse (← optStr j "requestId") (← optNat j "grantId")
      (← optStr j "executedOpDigest") (← j.getObjValAs? String "reason")
  | "observe" =>
    pure <| some <| .observe (← j.getObjValAs? String "requestId") (← j.getObjValAs? String "executedOpDigest")
      (← j.getObjValAs? String "authorizedEffect") (← j.getObjValAs? String "observedEffect")
      (← j.getObjValAs? Bool "match")
  | other => throw s!"unknown event kind {other}"

-- Checking a file --------------------------------------------------------------

structure Finding where
  index : Nat
  reason : String
  line : String

structure Summary where
  file : String
  events : Nat := 0
  conform : Nat := 0
  worldCheck : Nat := 0
  unmodelled : Nat := 0
  nonconform : List Finding := []
  parseErrors : List Finding := []
  final : State := {}

def Summary.ok (s : Summary) : Bool := s.nonconform.isEmpty && s.parseErrors.isEmpty

def checkLines (file : String) (lines : List String) : Summary := Id.run do
  let mut s : State := {}
  let mut out : Summary := { file }
  let mut i := 0
  for line in lines do
    match Json.parse line >>= parseEvent with
    | .error err => out := { out with parseErrors := out.parseErrors ++ [⟨i, err, line⟩] }
    | .ok none => pure ()
    | .ok (some e) =>
      out := { out with events := out.events + 1 }
      match stepCheck s e with
      | .conform s' => s := s'; out := { out with conform := out.conform + 1 }
      | .worldCheck s' => s := s'; out := { out with worldCheck := out.worldCheck + 1 }
      | .unmodelled s' _ => s := s'; out := { out with unmodelled := out.unmodelled + 1 }
      | .nonconform why =>
        -- state is NOT advanced past a non-conforming event
        out := { out with nonconform := out.nonconform ++ [⟨i, why, line⟩] }
    i := i + 1
  return { out with final := s }

def checkFile (path : System.FilePath) : IO Summary := do
  let text ← IO.FS.readFile path
  let lines := (text.splitOn "\n").filter (· ≠ "")
  return checkLines path.toString lines

def findingJson (f : Finding) : Json :=
  Json.mkObj [("index", toJson f.index), ("reason", toJson f.reason), ("event", toJson f.line)]

def summaryJson (s : Summary) : Json :=
  Json.mkObj [
    ("file", toJson s.file), ("events", toJson s.events), ("conform", toJson s.conform),
    ("worldCheck", toJson s.worldCheck), ("unmodelled", toJson s.unmodelled),
    ("nonconform", Json.arr (s.nonconform.map findingJson).toArray),
    ("parseErrors", Json.arr (s.parseErrors.map findingJson).toArray),
    ("finalState", Json.mkObj [("next", toJson s.final.next), ("intents", toJson s.final.intents.length),
      ("spent", toJson s.final.spent.length), ("executions", toJson s.final.executions.length)]),
    ("ok", toJson s.ok)]

def main : IO Unit := do
  let dir : System.FilePath := (← IO.getEnv "MAB_TRACE_DIR").getD "formal/traces"
  let files ← dir.walkDir
  let traces := (files.filter (·.extension == some "jsonl")).qsort (fun a b => a.toString < b.toString)
  let mut summaries : Array Summary := #[]
  for f in traces do
    summaries := summaries.push (← checkFile f)
  let total := summaries.foldl (fun n s => n + s.events) 0
  let bad := summaries.foldl (fun n s => n + s.nonconform.length + s.parseErrors.length) 0
  let conformingTraces := (summaries.filter (·.ok)).size
  for s in summaries do
    IO.println s!"conformance: {s.file}: {s.events} events, {s.conform} conform, {s.worldCheck} world-check, {s.unmodelled} unmodelled, {s.nonconform.length} NON-CONFORMING, {s.parseErrors.length} parse errors"
    for f in s.nonconform do
      IO.println s!"  NON-CONFORMING event {f.index}: {f.reason}"
      IO.println s!"    {f.line}"
    for f in s.parseErrors do
      IO.println s!"  PARSE ERROR line {f.index}: {f.reason}"
  IO.println s!"conformance: {traces.size} traces, {total} events, {conformingTraces} traces conform, {bad} non-conforming events (not a refinement proof)"
  let report := Json.mkObj [
    ("source", "formal/Conformance.lean"),
    ("scope", "decidable trace check of src/ transitions against the Boundary.lean transition system; not a refinement proof"),
    ("traceDir", toJson dir.toString), ("traces", toJson traces.size), ("events", toJson total),
    ("conformingTraces", toJson conformingTraces), ("nonconformingEvents", toJson bad),
    ("perTrace", Json.arr (summaries.map summaryJson))]
  IO.FS.writeFile "formal/conformance-report.json" (report.pretty ++ "\n")

-- Negative controls: the checker must go RED on each planted violation, or a
-- green run means nothing. Each is a one-event deviation from a conforming trace.
def g0 : Op := ⟨"d0", "corp/public/notes.md", 5⟩
def okTrace : List Event :=
  [ .authorize "r0" true none (some 0) g0 (requestOf g0), .execute "r0" 0 "d0",
    .observe "r0" "d0" "e" "e" true, .refuse (some "r0") (some 0) (some "d0") "spent",
    .authorize "r1" false (some "explicit-forbid") none g0 (requestOf g0) ]
example : traceOk okTrace = true := by native_decide
-- double spend
example : traceOk [ .authorize "r0" true none (some 0) g0 (requestOf g0), .execute "r0" 0 "d0", .execute "r0" 0 "d0" ] = false := by native_decide
-- execute an operation other than the granted one (the A1 shape)
example : traceOk [ .authorize "r0" true none (some 0) g0 (requestOf g0), .execute "r0" 0 "d1" ] = false := by native_decide
-- request not derived from the operation (Cedar saw a different byteLen)
example : traceOk [ .authorize "r0" true none (some 0) g0 ⟨"corp/public/notes.md", 0⟩ ] = false := by native_decide
-- grant minted on deny
example : traceOk [ .authorize "r0" false none (some 0) g0 (requestOf g0) ] = false := by native_decide
-- non-fresh grant id
example : traceOk [ .authorize "r0" true none (some 3) g0 (requestOf g0) ] = false := by native_decide
-- execution without a prepared grant
example : traceOk [ .execute "r0" 0 "d0" ] = false := by native_decide
-- observed effect differs from authorized
example : traceOk [ .authorize "r0" true none (some 0) g0 (requestOf g0), .execute "r0" 0 "d0", .observe "r0" "d0" "e" "f" false ] = false := by native_decide
-- refusal the model would NOT have refused (over-refusal is a finding too)
example : traceOk [ .authorize "r0" true none (some 0) g0 (requestOf g0), .refuse (some "r0") (some 0) (some "d0") "spent" ] = false := by native_decide

#eval main

end Conformance
