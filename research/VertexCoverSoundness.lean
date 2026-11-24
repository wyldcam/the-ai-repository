/-
  VertexCoverSoundness.lean
  Formal specification of NP Vertex Cover feasibility and strict weight-monotone
  redundancy pruning (formalizing post-solve witness cover-preservation checks).
  Zero external dependencies (pure Lean 4 core).
-/

namespace NSPL.FormalAudit

structure Graph (V : Type) where
  edges : List (V × V)

def IsVertexCover {V : Type} [DecidableEq V] (G : Graph V) (C : List V) : Prop :=
  ∀ e ∈ G.edges, e.1 ∈ C ∨ e.2 ∈ C

def coverWeight {V : Type} (w : V → Nat) (C : List V) : Nat :=
  C.foldl (fun acc v => acc + w v) 0

/-- Removing an element `u` whose neighbors are all already in `C` preserves edge coverage. -/
theorem erase_redundant_preserves_cover
    {V : Type} [DecidableEq V] (G : Graph V) (C : List V) (u : V)
    (hCov : IsVertexCover G C)
    (hRed : ∀ e ∈ G.edges, (e.1 = u → e.2 ∈ C ∧ e.2 ≠ u) ∧ (e.2 = u → e.1 ∈ C ∧ e.1 ≠ u)) :
    IsVertexCover G (C.erase u) := by
  intro e he
  rcases hCov e he with h1 | h2
  · by_cases hu1 : e.1 = u
    · obtain ⟨h2C, h2ne⟩ := (hRed e he).1 hu1
      exact Or.inr (List.mem_erase_of_ne h2ne |>.mpr h2C)
    · exact Or.inl (List.mem_erase_of_ne hu1 |>.mpr h1)
  · by_cases hu2 : e.2 = u
    · obtain ⟨h1C, h1ne⟩ := (hRed e he).2 hu2
      exact Or.inl (List.mem_erase_of_ne h1ne |>.mpr h1C)
    · exact Or.inr (List.mem_erase_of_ne hu2 |>.mpr h2)

end NSPL.FormalAudit