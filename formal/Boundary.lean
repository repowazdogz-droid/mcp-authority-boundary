/-
Trace semantics for authorization, persistent intent, and single-use execution.
The policy and request derivation are explicit parameters. This proves properties
of this model, not a refinement of the TypeScript implementation or of disk I/O.
Operations are compared by value here; a digest implementation additionally
requires collision resistance and a correct canonical encoding.
-/
namespace Boundary

structure Operation where
  resource : Nat
  payload : List UInt8
deriving DecidableEq, Repr

structure Request where
  resource : Nat
  byteLen : Nat
deriving DecidableEq, Repr

def requestOf (op : Operation) : Request := ⟨op.resource, op.payload.length⟩

structure Grant where
  id : Nat
  op : Operation
  request : Request
deriving DecidableEq, Repr

structure State where
  next : Nat := 0
  intents : List Grant := []
  spent : List Nat := []
  executions : List Grant := []
deriving Repr

inductive Step (policy : Request → Bool) : State → State → Prop
  | authorize (s : State) (g : Grant)
      (fresh : g.id = s.next)
      (bound : g.request = requestOf g.op)
      (allowed : policy g.request = true) :
      Step policy s { s with next := s.next + 1, intents := g :: s.intents }
  | execute (s : State) (g : Grant)
      (prepared : g ∈ s.intents)
      (unused : g.id ∉ s.spent) :
      Step policy s { s with spent := g.id :: s.spent, executions := g :: s.executions }

inductive Reachable (policy : Request → Bool) : State → Prop
  | initial : Reachable policy {}
  | next {s s' : State} : Reachable policy s → Step policy s s' → Reachable policy s'

def Invariant (policy : Request → Bool) (s : State) : Prop :=
  (∀ g ∈ s.intents, g.request = requestOf g.op ∧ policy g.request = true) ∧
  (∀ g ∈ s.executions, g ∈ s.intents) ∧
  s.executions.map Grant.id = s.spent ∧ s.spent.Nodup

theorem invariant_step {policy : Request → Bool} {s s' : State}
    (inv : Invariant policy s) (step : Step policy s s') : Invariant policy s' := by
  rcases inv with ⟨valid, recorded, spent, unique⟩
  cases step with
  | authorize g fresh bound allowed =>
    refine ⟨?_, ?_, spent, unique⟩
    · intro h member
      simp only [List.mem_cons] at member
      rcases member with rfl | member
      · exact ⟨bound, allowed⟩
      · exact valid h member
    · intro h member
      exact List.mem_cons_of_mem g (recorded h member)
  | execute g prepared unused =>
    refine ⟨valid, ?_, ?_, ?_⟩
    · intro h member
      simp only [List.mem_cons] at member
      rcases member with rfl | member
      · exact prepared
      · exact recorded h member
    · simp only [List.map_cons, spent]
    · exact List.nodup_cons.mpr ⟨unused, unique⟩

theorem reachable_invariant {policy : Request → Bool} {s : State}
    (reachable : Reachable policy s) : Invariant policy s := by
  induction reachable with
  | initial => simp [Invariant]
  | next _ step ih => exact invariant_step ih step

theorem execution_has_recorded_allow {policy : Request → Bool} {s : State}
    (reachable : Reachable policy s) (g : Grant) (executed : g ∈ s.executions) :
    g ∈ s.intents ∧ g.request = requestOf g.op ∧ policy g.request = true := by
  rcases reachable_invariant reachable with ⟨valid, recorded, _⟩
  exact ⟨recorded g executed, valid g (recorded g executed)⟩

theorem grants_execute_at_most_once {policy : Request → Bool} {s : State}
    (reachable : Reachable policy s) : (s.executions.map Grant.id).Nodup := by
  rcases reachable_invariant reachable with ⟨_, _, equal, unique⟩
  rw [equal]
  exact unique

-- A positive execution and the original size-mismatch witness.
def small : Operation := ⟨7, [1, 2, 3]⟩
def budget (r : Request) : Bool := r.byteLen ≤ 4096
def granted : Grant := ⟨0, small, requestOf small⟩

example : Reachable budget ⟨1, [granted], [0], [granted]⟩ := by
  apply Reachable.next (s := ⟨1, [granted], [], []⟩)
  · exact Reachable.next Reachable.initial
      (Step.authorize {} granted rfl rfl (by decide))
  · exact Step.execute _ granted (by simp) (by simp [granted])

theorem legacy_size_mismatch :
    budget ⟨7, 0⟩ = true ∧ budget ⟨7, 100000⟩ = false := by decide

-- Removing the unused premise permits spending the same grant twice.
theorem reuse_mutant_breaks_uniqueness :
    ¬ ([granted, granted].map Grant.id).Nodup := by decide

inductive ReuseStep (policy : Request → Bool) : State → State → Prop
  | normal {s s' : State} : Step policy s s' → ReuseStep policy s s'
  | execute (s : State) (g : Grant) (prepared : g ∈ s.intents) :
      ReuseStep policy s { s with spent := g.id :: s.spent, executions := g :: s.executions }

inductive ReuseReachable (policy : Request → Bool) : State → Prop
  | initial : ReuseReachable policy {}
  | next {s s' : State} : ReuseReachable policy s → ReuseStep policy s s' → ReuseReachable policy s'

theorem reuse_mutant_has_bad_trace :
    ∃ s, ReuseReachable budget s ∧ ¬ (s.executions.map Grant.id).Nodup := by
  refine ⟨⟨1, [granted], [0, 0], [granted, granted]⟩, ?_, by decide⟩
  apply ReuseReachable.next (s := ⟨1, [granted], [0], [granted]⟩)
  · apply ReuseReachable.next (s := ⟨1, [granted], [], []⟩)
    · exact ReuseReachable.next ReuseReachable.initial
        (ReuseStep.normal (Step.authorize {} granted rfl rfl (by decide)))
    · exact ReuseStep.execute _ granted (by simp)
  · exact ReuseStep.execute _ granted (by simp)

-- A completed-record list can be empty even while an execution remains.
-- Persisting intents exposes this gap; it does not establish an external effect.
theorem truncation_can_hide_completion :
    ∃ (executions completions : List Grant), executions ≠ [] ∧ completions = [] := by
  exact ⟨[granted], [], by simp, rfl⟩

#print axioms execution_has_recorded_allow
#print axioms grants_execute_at_most_once
#print axioms legacy_size_mismatch
#print axioms reuse_mutant_breaks_uniqueness
#print axioms reuse_mutant_has_bad_trace
end Boundary
