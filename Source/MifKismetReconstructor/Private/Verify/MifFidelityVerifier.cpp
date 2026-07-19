// Level-1 fidelity self-check: diff the RECOMPILED bytecode of a reconstructed function against the COOKED original,
// using the SAME disassembler on both sides. Compile-success proves the graph is VALID; this proves it is EQUIVALENT.
//
// Model: canonicalise each top-level statement to a string, then compare strings. Chosen over a structural JSON diff
// because it yields a printable first-diff a human can read, makes each rule a one-line transform, and is trivially
// testable. Sub-expressions are emitted recursively and parenthesised, so nesting is preserved exactly.
//
// STRICT vs LOSSY (this is the whole verdict mechanism — read before touching a rule):
//   Each side is normalised TWICE from ONE disassembly.
//     * STRICT applies only information-PRESERVING rules (side-relative alias resolution, byte-offset→ordinal,
//       derived/diagnostic field drops). Equal under strict ⇒ IDENTICAL.
//     * LOSSY additionally applies the rules that deliberately destroy information (α-rename of compiler temps,
//       LWC float/double width folding, text localisation keys). Equal ONLY under lossy ⇒ EQUIVALENT.
//     * Unequal under lossy ⇒ DRIFT.
//   The obvious cheaper design — one pass with a "a lossy rule fired" flag — is WRONG, and wrong in the direction
//   that destroys the metric: a rule FIRING is not a rule MASKING a difference. Every function that so much as
//   mentions a compiler temp fires the α-rename, so IDENTICAL would collapse to ~0 and everything would read
//   EQUIVALENT — the two verdicts would stop distinguishing anything. Normalising twice is the cheap correct version.
//
// CHILD MODE ONLY. See CompiledBlueprintReconstructor.h: a sibling copy mints into the transient package and COPIES
// components, so component references differ by object path on every BP → systematic false drift. Callers refuse it.

// DRIFT IS NOT ONE BUCKET. A drifting function is handed to MifDriftClassifier, which splits it into INTENTIONAL (a
// deliberate, permanent shape choice — the flow-stack elision, the branched out-param's synthesized local) and REAL
// drift, the number a release gates on. The classifier runs ONLY on the ++Drift path below and can only ever SUBDIVIDE
// that bucket: Identical/Equivalent/Missing/Uncomparable/Compared/Scored()/Score() are byte-identical with it on or off
// (`mif.kr.ClassifyIntentional 0`). That containment is the whole safety story — see MifDriftClassifier.h.

#include "MifReconstructorDebug.h"
#include "Toolkit/KismetBytecodeDisassemblerJson.h"
#include "Verify/MifDriftClassifier.h"
#include "CompiledBlueprintReconstructor.h"

#include "Engine/Blueprint.h"
#include "Engine/BlueprintGeneratedClass.h"
#include "UObject/Class.h"
#include "UObject/UnrealType.h"
#include "Dom/JsonObject.h"
#include "Dom/JsonValue.h"
#include "Misc/StringBuilder.h"
#include "HAL/IConsoleManager.h"

namespace MifKr::Fidelity
{
	// `mif.kr.DumpFull 1` prints the COMPLETE cooked-vs-recon normalized statement stream for every compared
	// function (not just the ±2 window around the first drift). The testbed loop needs the whole stream to see
	// what happens after the first divergence — the window hides the cascade. Off by default (spammy on big BPs).
	static TAutoConsoleVariable<int32> CVarDumpFull(
		TEXT("mif.kr.DumpFull"),
		0,
		TEXT("MifKr fidelity: dump the full cooked-vs-recon statement stream for every compared function (0=off)."),
		ECVF_Default);

	struct FCtx
	{
		UFunction* Func = nullptr;          // this side's function (used to classify locals as params)
		FString SelfScopePath;              // Func->GetTypedOuter<UClass>()->GetPathName() — what "<SELF>" means HERE
		TSet<FString> ReconIdentities;      // every path that IS the reconstructed class (empty on the cooked side)
		FString SourceClassPath;            // cooked BPGC path — the canonical identity BOTH sides fold onto
		TMap<int32, int32> OffsetToOrdinal; // R2/R3: byte offset → statement ordinal
		TMap<FString, int32> Alpha;         // R6: compiler-temp local name → id (per emission pass, never shared)
		bool bStrict = true;                // true ⇒ preserving rules only (see the header comment)
	};

	// R1 — the corrected self-handling. "<SELF>" is NOT free, it is a LOSSY, SIDE-RELATIVE alias: the disassembler
	// writes it whenever an object == its SelfScope (PropertyTypeHelper.cpp:95, SelfScope set at
	// KismetBytecodeDisassemblerJson.cpp:950). SelfScope differs per side, so a pin typed BP_Foo_C emits "<SELF>" on
	// the cooked side but the full path on the recon side (where SelfScope is the CHILD class) — a mismatch on every
	// self-typed pin. So: resolve the alias per side, THEN fold every recon identity onto the source class.
	//
	// Both identities must fold (see [3]): a self-CALL resolves against the new BP's TRANSIENT SkeletonGeneratedClass
	// (MifReconstructCommand.cpp:38 says so explicitly), not its GeneratedClass, so folding only GeneratedClass would
	// leave every self-call pin pointing at a skeleton path that matches nothing.
	// This is information-PRESERVING (it resolves an alias and applies a known identity), so it runs in BOTH passes.
	static FString CanonClass(const FString& In, const FCtx& C)
	{
		FString P = In;
		if (P == TEXT("<SELF>")) { P = C.SelfScopePath; }
		if (C.ReconIdentities.Contains(P)) { P = C.SourceClassPath; }
		return P;
	}

	// R6 support: params/out-params are signature, not scratch — they are compared LITERALLY.
	static bool IsParam(UFunction* F, const FString& N)
	{
		if (!F || N.IsEmpty()) { return false; }
		const FProperty* P = F->FindPropertyByName(FName(*N));   // UStruct::FindPropertyByName — Class.h:474
		return P && P->HasAnyPropertyFlags(CPF_Parm);
	}

	// Every field the disassembler fills via SafePathName() or SerializeObjectRef() — i.e. every class-identity path.
	static const TSet<FString>& ClassPathFields()
	{
		static const TSet<FString> S = {
			TEXT("Object"), TEXT("Class"), TEXT("Struct"), TEXT("ContextClass"),
			TEXT("InterfaceClass"), TEXT("ObjectClass"), TEXT("MemberParent"),
			TEXT("PinSubCategoryObject"), TEXT("TerminalSubCategoryObject")
		};
		return S;
	}

	// R2 StatementIndex (a BYTE OFFSET, not an ordinal — any operand-width change shifts every one of them)
	// R4 SkipOffsetForNull (a byte count of the sub-expression: fully derived from operands we already compare;
	//    keeping it would double-report one defect as N diffs)
	// R5 LineNumber (a source line number — cannot survive reconstruction, no runtime meaning)
	// R9 IsSelfContext (side-relative, re-derived below from the canonicalised parent)
	// Op/AtIndex (diagnostics on the Unknown node — which already forces UNCOMPARABLE anyway)
	static const TSet<FString>& DroppedFields()
	{
		static const TSet<FString> S = {
			TEXT("StatementIndex"), TEXT("SkipOffsetForNull"), TEXT("LineNumber"), TEXT("IsSelfContext"),
			TEXT("Op"), TEXT("AtIndex")
		};
		return S;
	}

	// R7 (a) — LWC width folding. The disassembler emits a DIFFERENT Inst per width: "FloatConst" vs "DoubleConst"
	// (KismetBytecodeDisassemblerJson.cpp:502/:509) and "Vector3fConst" vs "VectorConst" (:607/:598). A float that LWC
	// legitimately promoted to double therefore differs in the OPCODE NAME, so rewriting only the number can never make
	// the two sides converge — the name must be folded too, BEFORE it is emitted. Lossy: it erases a real width change.
	static FString CanonInst(const FString& Inst)
	{
		if (Inst == TEXT("FloatConst") || Inst == TEXT("DoubleConst"))      { return TEXT("RealConst"); }
		if (Inst == TEXT("Vector3fConst") || Inst == TEXT("VectorConst"))   { return TEXT("VecConst"); }
		return Inst;
	}

	// R7 (b) — which numeric fields hold a REAL. Scoped by instruction, never by key name alone: "Value" is also the
	// key for IntConst/Int64Const/UInt64Const/ByteConst, and quantising an int64 to float precision would silently
	// destroy up to 11 bits of a literal — masking exactly the kind of real drift this tool exists to find.
	static bool IsRealValuedKey(const FString& EffInst, const FString& Key)
	{
		if (EffInst == TEXT("RealConst") || EffInst == TEXT("FloatConst") || EffInst == TEXT("DoubleConst"))
		{
			return Key == TEXT("Value");
		}
		if (EffInst == TEXT("VecConst") || EffInst == TEXT("VectorConst") || EffInst == TEXT("Vector3fConst"))
		{
			return Key == TEXT("X") || Key == TEXT("Y") || Key == TEXT("Z");
		}
		if (EffInst == TEXT("RotationConst"))   // :590-592 — Pitch/Yaw/Roll, NOT X/Y/Z
		{
			return Key == TEXT("Pitch") || Key == TEXT("Yaw") || Key == TEXT("Roll");
		}
		if (EffInst.StartsWith(TEXT("TransformConst.")))   // :628-645 — nested Rotation{XYZW}/Translation{XYZ}/Scale{XYZ}
		{
			return Key == TEXT("X") || Key == TEXT("Y") || Key == TEXT("Z") || Key == TEXT("W");
		}
		return false;
	}

	// R3 — which "Offset" fields are CODE OFFSETS that must be rewritten to statement ordinals. Scoped by instruction:
	// EX_AutoRtfmTransact also writes an "Offset" (:911), so a rewrite keyed on the field NAME alone would silently
	// catch it (or, if only the three jump opcodes were listed, silently miss it and compare a raw byte offset).
	static bool IsCodeOffsetField(const FString& EffInst, const FString& Key)
	{
		if (Key != TEXT("Offset")) { return false; }
		return EffInst == TEXT("Jump")               // :264
			|| EffInst == TEXT("JumpIfNot")          // :766
			|| EffInst == TEXT("PushExecutionFlow")  // :823
			|| EffInst == TEXT("AutoRtfmTransact");  // :911
	}

	static void Emit(const TSharedPtr<FJsonObject>& E, FCtx& C, FStringBuilderBase& Out, const FString& ContextInst);

	static void EmitValue(const FString& EffInst, const FString& Key, const TSharedPtr<FJsonValue>& V, FCtx& C, FStringBuilderBase& Out)
	{
		if (!V.IsValid()) { Out << Key << TEXT("=<null> "); return; }

		switch (V->Type)
		{
		case EJson::Object:
		{
			if (!Key.IsEmpty()) { Out << Key << TEXT("="); }
			// Sub-objects with no "Inst" of their own (TransformConst's Rotation/Translation/Scale, pin types,
			// DelegateSignatureFunction) inherit a synthetic "<ParentInst>.<Key>" context so the rules above can
			// still scope themselves. Identical on both sides, so it cannot itself cause drift.
			Emit(V->AsObject(), C, Out, Key.IsEmpty() ? EffInst : (EffInst + TEXT(".") + Key));
			break;
		}
		case EJson::Array:
		{
			if (!Key.IsEmpty()) { Out << Key << TEXT("="); }
			Out << TEXT("[");
			for (const TSharedPtr<FJsonValue>& It : V->AsArray())
			{
				EmitValue(EffInst, FString(), It, C, Out);
				Out << TEXT(",");
			}
			Out << TEXT("]");
			break;
		}
		case EJson::String:
		{
			FString S = V->AsString();
			if (ClassPathFields().Contains(Key))
			{
				S = CanonClass(S, C);                                                        // R1 (preserving)
			}
			else if (!C.bStrict && (Key == TEXT("LocalizationKey") || Key == TEXT("LocalizationNamespace")))
			{
				// R8 — a differing key changes the localisation lookup: a real but non-control-flow loss. Report it as
				// EQUIVALENT (the lossy pass folds it), never as IDENTICAL. TextLiteralType + SourceString stay strict.
				S = TEXT("<key>");
			}
			Out << Key << TEXT("='") << S << TEXT("'");
			break;
		}
		case EJson::Number:
		{
			const double D = V->AsNumber();
			if (IsCodeOffsetField(EffInst, Key))
			{
				// R3 — absolute byte offset → statement ordinal. An off-boundary target is a REAL signal (it means the
				// jump lands mid-statement), so it is surfaced, not silently dropped.
				const int32* Ord = C.OffsetToOrdinal.Find((int32)D);
				Out << TEXT("Offset=#");
				if (Ord) { Out << *Ord; }
				else     { Out << TEXT("unaligned(") << (int32)D << TEXT(")"); }
			}
			else if (!C.bStrict && IsRealValuedKey(EffInst, Key))
			{
				// R7 (c) — quantise BOTH sides to float precision so a float and its LWC-widened double land on the
				// SAME token. A "%.9g" (or %.17g) string compare cannot do this: 0.1f prints 0.100000001 and 0.1
				// prints 0.1, so every widened literal would false-DRIFT. Round-tripping through float first is what
				// makes the two converge.
				Out << Key << TEXT("=real(") << FString::Printf(TEXT("%.7g"), (double)(float)D) << TEXT(")");
			}
			else
			{
				// Strict pass (and every non-real number): full precision, no information discarded.
				Out << Key << TEXT("=") << FString::Printf(TEXT("%.17g"), D);
			}
			break;
		}
		case EJson::Boolean:
			Out << Key << TEXT("=") << (V->AsBool() ? TEXT("1") : TEXT("0"));
			break;
		default:
			Out << Key << TEXT("=null");
			break;
		}
		Out << TEXT(" ");
	}

	static void Emit(const TSharedPtr<FJsonObject>& E, FCtx& C, FStringBuilderBase& Out, const FString& ContextInst)
	{
		if (!E.IsValid()) { Out << TEXT("(null)"); return; }

		FString RawInst;
		E->TryGetStringField(TEXT("Inst"), RawInst);

		// R7 (a) — fold the width-bearing opcode name BEFORE emitting it. Lossy-only: under the strict pass a
		// FloatConst must still read as a FloatConst, or a genuine width change would be scored IDENTICAL.
		const FString Inst = C.bStrict ? RawInst : CanonInst(RawInst);
		const FString EffInst = Inst.IsEmpty() ? ContextInst : Inst;

		Out << TEXT("(") << EffInst << TEXT(" ");

		// R6 — α-rename compiler temps. The compiler names them freely (CallFunc_Map_Find_Value,
		// K2Node_MakeStruct_…) and our node GUIDs differ from the original author's, so a literal comparison is
		// guaranteed to fail on nearly every function. α-equivalence is the correct relation. Params/out-params and
		// InstanceVariable/DefaultVariable names are signature/state, NOT scratch — always literal.
		bool bAlphaRenamed = false;
		if (RawInst == TEXT("LocalVariable"))
		{
			FString VN;
			E->TryGetStringField(TEXT("VariableName"), VN);
			if (!C.bStrict && !IsParam(C.Func, VN))
			{
				int32* Id = C.Alpha.Find(VN);
				if (!Id) { Id = &C.Alpha.Add(VN, C.Alpha.Num()); }   // numbered by FIRST APPEARANCE in the stream
				Out << TEXT("VariableName=%L") << *Id << TEXT(" ");
				bAlphaRenamed = true;
			}
		}

		// R9 — re-derive IsSelfContext from the R1-canonicalised parent rather than trusting the disassembler's
		// side-relative flag (:432 computes it against that side's SelfScope, so it is asymmetric by construction).
		if (RawInst == TEXT("CallMulticastDelegate"))
		{
			const TSharedPtr<FJsonObject>* Sig = nullptr;
			if (E->TryGetObjectField(TEXT("DelegateSignatureFunction"), Sig) && Sig && Sig->IsValid())
			{
				FString MP;
				(*Sig)->TryGetStringField(TEXT("MemberParent"), MP);
				Out << TEXT("SelfCtx=") << (CanonClass(MP, C) == C.SourceClassPath ? TEXT("1") : TEXT("0")) << TEXT(" ");
			}
		}

		// JSON map order is not stable across sides — a canonical key order is mandatory.
		TArray<FString> Keys;
		E->Values.GetKeys(Keys);
		Keys.Sort();
		for (const FString& K : Keys)
		{
			if (K == TEXT("Inst")) { continue; }
			if (DroppedFields().Contains(K)) { continue; }                                  // R2/R4/R5/R9
			if (bAlphaRenamed && K == TEXT("VariableName")) { continue; }                   // already emitted (R6)
			EmitValue(EffInst, K, E->Values[K], C, Out);
		}
		Out << TEXT(")");
	}

	// Disassemble ONE function ONCE, then emit its canonical statement stream TWICE — strict and lossy.
	// Returns false if the function has no bytecode or the disassembly aborted.
	// bOutUncomparable: disassembly aborted (R12) or the stream contains an <unresolved> pointer (R11).
	// R13 — EDITOR-ONLY DEBUG NO-OPS. The reconstructed copy is compiled IN THE EDITOR, so the K2 backend interleaves
	// Blueprint-debugger instructions the COOKED (shipping) bytecode never contains. The engine documents them as pure
	// no-ops (UObject/Script.h): EX_Breakpoint 0x50, EX_WireTracepoint 0x5A, EX_Tracepoint 0x5E — each commented
	// "Only observed in the editor, otherwise it behaves like EX_Nothing" — plus EX_InstrumentationEvent 0x6A.
	// They carry ZERO semantics, so dropping them is information-PRESERVING and belongs in the STRICT pass (a function
	// can still score IDENTICAL). Without this every reconstructed function drifts at statement 0 against every cooked
	// original — a blanket false 0%, which is exactly what the first real run produced.
	static bool IsEditorOnlyDebugStatement(const FString& Inst)
	{
		return Inst == TEXT("Tracepoint") || Inst == TEXT("WireTracepoint")
			|| Inst == TEXT("Breakpoint") || Inst == TEXT("InstrumentationEvent");
	}

	static bool Normalize(UFunction* F, const TSet<FString>& ReconIdentities, const FString& SourceClassPath,
	                      TArray<FString>& OutStrict, TArray<FString>& OutLossy, bool& bOutUncomparable)
	{
		OutStrict.Reset();
		OutLossy.Reset();
		bOutUncomparable = false;
		if (!F || F->Script.Num() == 0) { return false; }

		FKismetBytecodeDisassemblerJson Dis;
		TArray<TSharedPtr<FJsonValue>> Vals = Dis.SerializeFunction(F);
		if (Dis.bDisassemblyFailed)
		{
			// R12 — an aborted disassembly means the tail of the stream is unknown, not empty. Never score it.
			bOutUncomparable = true;
#if MIF_KR_DEBUG
			UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[fidelity] %s: disassembly aborted at opcode 0x%02X (byte %d) → UNCOMPARABLE"),
				*F->GetName(), Dis.FailedOpcode, Dis.FailedAtIndex);
#endif
			return false;
		}

		// Collect EVERY statement first, flagging the editor-only debug no-ops (R13) rather than dropping them here:
		// a jump can TARGET a tracepoint's byte offset, and that offset must still resolve (see the ordinal map below).
		TArray<TSharedPtr<FJsonObject>> Raw;
		TArray<bool> bRawIsDebug;
		for (const TSharedPtr<FJsonValue>& V : Vals)
		{
			if (!V.IsValid()) { continue; }
			TSharedPtr<FJsonObject> O = V->AsObject();
			if (!O.IsValid()) { continue; }
			FString Inst;
			O->TryGetStringField(TEXT("Inst"), Inst);
			if (Inst == TEXT("EndOfScript")) { continue; }   // mirrors MifReconstructCommand.cpp:77
			Raw.Add(O);
			bRawIsDebug.Add(IsEditorOnlyDebugStatement(Inst));
		}

		// R13 — survivors are the real statements; the debug no-ops are never emitted or compared.
		TArray<TSharedPtr<FJsonObject>> Stmts;
		TArray<int32> RawToOrdinal;
		RawToOrdinal.SetNum(Raw.Num());
		for (int32 i = 0; i < Raw.Num(); ++i)
		{
			if (!bRawIsDebug[i]) { RawToOrdinal[i] = Stmts.Num(); Stmts.Add(Raw[i]); }
			else                 { RawToOrdinal[i] = INDEX_NONE; }
		}
		// A debug statement behaves like EX_Nothing, so a jump landing on it simply falls through: resolve its offset to
		// the NEXT surviving statement. Walk BACKWARD so each dropped run inherits the following survivor's ordinal
		// (trailing debug statements resolve past-the-end, matching a cooked jump to the end of the stream).
		{
			int32 Next = Stmts.Num();
			for (int32 i = Raw.Num() - 1; i >= 0; --i)
			{
				if (RawToOrdinal[i] != INDEX_NONE) { Next = RawToOrdinal[i]; }
				else                               { RawToOrdinal[i] = Next; }
			}
		}

#if MIF_KR_DEBUG
		if (Raw.Num() != Stmts.Num())
		{
			UE_LOG(LogMifKismetReconstructor, Verbose, TEXT("[fidelity] %s: dropped %d editor-only debug statement(s) of %d"),
				*F->GetName(), Raw.Num() - Stmts.Num(), Raw.Num());
		}
#endif

		UClass* Outer = F->GetTypedOuter<UClass>();

		// PASS 1 — R2/R3: byte offset → ordinal. Jumps are frequently FORWARD, so the whole map must exist before any
		// statement is emitted. Built over RAW (not survivors) so a jump targeting a dropped debug statement's offset
		// still resolves — to the ordinal of the next real statement.
		TMap<int32, int32> OffsetToOrdinal;
		for (int32 i = 0; i < Raw.Num(); ++i)
		{
			double Off = 0.0;
			if (Raw[i]->TryGetNumberField(TEXT("StatementIndex"), Off))
			{
				OffsetToOrdinal.Add((int32)Off, RawToOrdinal[i]);
			}
		}

		// PASS 2 — emit, once per mode. The α-id map MUST be rebuilt per mode (ids are assigned by first appearance).
		auto EmitAll = [&](bool bStrict, TArray<FString>& Dest)
		{
			FCtx C;
			C.Func            = F;
			C.SelfScopePath   = Outer ? Outer->GetPathName() : FString();
			C.ReconIdentities = ReconIdentities;
			C.SourceClassPath = SourceClassPath;
			C.OffsetToOrdinal = OffsetToOrdinal;
			C.bStrict         = bStrict;

			for (int32 i = 0; i < Stmts.Num(); ++i)
			{
				TStringBuilder<1024> SB;
				Emit(Stmts[i], C, SB, FString());
				Dest.Add(FString(SB.ToString()));
			}
		};
		EmitAll(/*bStrict*/ true,  OutStrict);
		EmitAll(/*bStrict*/ false, OutLossy);

		// R11 — an <unresolved> pointer means the cooked side itself names an object we cannot identify. You cannot
		// diff against an unknown; scoring it either way would be a lie. Checked on the strict stream (nothing elided).
		for (const FString& S : OutStrict)
		{
			if (S.Contains(TEXT("<unresolved>"))) { bOutUncomparable = true; break; }
		}
		return true;
	}

	static bool VerifyBlueprint(UBlueprintGeneratedClass* SourceBPGC, UBlueprint* ReconBP,
	                            const TArray<UFunction*>& AttemptedFuncs, FBlueprintFidelityReport& Out)
	{
		if (!SourceBPGC || !ReconBP) { return false; }

		// L2 — GeneratedClass, NEVER SkeletonGeneratedClass: skeleton UFunctions carry signatures with Script.Num()==0,
		// so reading the recon side from the skeleton would make every function look empty (MISSING / empty-vs-empty).
		// Only valid after FKismetEditorUtilities::CompileBlueprint has returned, which the callers guarantee.
		UClass* ReconClass = ReconBP->GeneratedClass;
		if (!ReconClass)
		{
			UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[fidelity] %s: recon BP has no GeneratedClass — cannot verify."), *ReconBP->GetName());
			return false;
		}

		// R1/[3] — BOTH recon identities fold onto the source class. GeneratedClass is what most references resolve
		// against; SkeletonGeneratedClass is what a SELF-CALL resolves against (it is the transient class the
		// reconstruction pipeline wires self-references to). Missing either leaves a whole class of pins false-drifting.
		TSet<FString> ReconIdentities;
		ReconIdentities.Add(ReconClass->GetPathName());
		if (ReconBP->SkeletonGeneratedClass)
		{
			ReconIdentities.Add(ReconBP->SkeletonGeneratedClass->GetPathName());
		}
		const FString SourcePath = SourceBPGC->GetPathName();
		const FString BPName = SourceBPGC->GetName();
		TMap<FString, int32> IntentCounts;   // reason -> count, serialised into Out.IntentTally at the end

		for (UFunction* CookedFunc : AttemptedFuncs)
		{
			if (!CookedFunc || CookedFunc->Script.Num() == 0) { continue; }
			const FString FnName = CookedFunc->GetName();

			// L1 — ExcludeSuper is MANDATORY, not a preference. FindFunctionByName defaults to IncludeSuper
			// (Class.h:3028), and in CHILD mode the super IS the cooked class (CompiledBlueprintCopyAction.cpp:608),
			// so the default would walk up and hand back the COOKED function — we would diff it against ITSELF and
			// report a permanent, unfalsifiable 100%. A total reconstruction failure would score perfectly.
			UFunction* ReconFunc = ReconClass->FindFunctionByName(FName(*FnName), EIncludeSuperFlag::ExcludeSuper);
			if (!ReconFunc || ReconFunc->Script.Num() == 0)
			{
				// A real failure: the cooked function had a body and the child has no own-class override with one.
				++Out.Missing;
				if (Out.Drift == 0 && Out.FirstDrift.IsEmpty())
				{
					Out.FirstDrift = FString::Printf(TEXT("%s: MISSING (no own-class override with bytecode)"), *FnName);
				}
				continue;
			}

			// Belt-and-braces on L1: if this ever resolves to the cooked function itself, the ExcludeSuper contract
			// has regressed. Soft-degrade — a decompiler must never assert on reconstructed data — but count it as
			// UNCOMPARABLE, never as a pass. A self-diff would otherwise be a guaranteed silent IDENTICAL.
			if (ReconFunc == CookedFunc)
			{
				++Out.Uncomparable;
				UE_LOG(LogMifKismetReconstructor, Error,
					TEXT("[fidelity] %s resolved to the COOKED function itself — ExcludeSuper regression. Counted UNCOMPARABLE, not scored."), *FnName);
				continue;
			}

			TArray<FString> CookedStrict, CookedLossy, ReconStrict, ReconLossy;
			bool bUncA = false, bUncB = false;
			const bool bOkA = Normalize(CookedFunc, ReconIdentities, SourcePath, CookedStrict, CookedLossy, bUncA);
			const bool bOkB = Normalize(ReconFunc,  ReconIdentities, SourcePath, ReconStrict,  ReconLossy,  bUncB);
			if (!bOkA || !bOkB || bUncA || bUncB) { ++Out.Uncomparable; continue; }          // R11/R12

			++Out.Compared;

			if (CVarDumpFull.GetValueOnAnyThread() != 0)
			{
				const int32 Rows = FMath::Max(CookedLossy.Num(), ReconLossy.Num());
				UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[dumpfull] %s  (cooked %d stmts | recon %d stmts)"),
					*FnName, CookedLossy.Num(), ReconLossy.Num());
				for (int32 i = 0; i < Rows; ++i)
				{
					UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[dumpfull]  %3d | %-90s | %s"), i,
						CookedLossy.IsValidIndex(i) ? *CookedLossy[i] : TEXT("-"),
						ReconLossy.IsValidIndex(i)  ? *ReconLossy[i]  : TEXT("-"));
				}
			}

			auto FirstDiffIndex = [](const TArray<FString>& A, const TArray<FString>& B) -> int32
			{
				const int32 N = FMath::Min(A.Num(), B.Num());
				for (int32 i = 0; i < N; ++i)
				{
					if (A[i] != B[i]) { return i; }
				}
				return (A.Num() != B.Num()) ? N : INDEX_NONE;   // a length difference IS a difference, at index N
			};

			if (FirstDiffIndex(CookedStrict, ReconStrict) == INDEX_NONE)
			{
				++Out.Identical;   // equal with NO information discarded
				continue;
			}

			const int32 LossyDiff = FirstDiffIndex(CookedLossy, ReconLossy);
			if (LossyDiff == INDEX_NONE)
			{
				++Out.Equivalent;  // equal only once a lossy rule folded the difference
				continue;
			}

			// The streams provably differ under lossy. Ask the classifier whether every difference is a deliberate,
			// permanent shape choice. It CLAIMS positively or not at all — anything unclaimed, ambiguous, or over a cap
			// lands here as REAL, which is the safe direction (a known-intentional drift sitting in REAL only
			// UNDERSTATES fidelity). It can never produce an Identical or an Equivalent.
			const MifKr::DriftClassify::FVerdict Verdict =
				MifKr::DriftClassify::Classify(BPName, FnName, CookedLossy, ReconLossy);

			if (Verdict.bIntentional)
			{
				++Out.Intentional;
				for (const FString& R : Verdict.Reasons) { ++IntentCounts.FindOrAdd(R); }
				if (Out.FirstIntentional.IsEmpty())
				{
					// One audit sample per BP — this exists so a human can hand-verify claimed functions (spec 6.3).
					Out.FirstIntentional = FString::Printf(TEXT("%s: INTENTIONAL(%s) cooked %s || recon %s"),
						*FnName, *FString::Join(Verdict.Reasons, TEXT("+")),
						Verdict.RootCooked.IsEmpty() ? TEXT("<no counterpart>") : *Verdict.RootCooked,
						Verdict.RootRecon.IsEmpty()  ? TEXT("<no counterpart>") : *Verdict.RootRecon);
				}
				continue;
			}

			++Out.Drift;
			if (Out.Drift == 1)   // the first REAL drift outranks any earlier MISSING note
			{
				if (Verdict.bHasRoot)
				{
					// ROOT-CAUSE attribution: the first UNCLAIMED edit, not the first raw stream difference. Today's
					// FirstDrift on a flow-stack function names the known-intentional PushExecutionFlow at stmt 0 and
					// buries the actual bug behind it; and after one insertion the reported "@ stmt 6: Jump #31 vs #38"
					// is the CASCADE, not the signal. Derived jump-ordinal shifts are resolved through the alignment
					// and attributed to their root, so they can never be reported as a drift of their own.
					Out.FirstDrift = FString::Printf(TEXT("%s @ cooked stmt %d / recon stmt %d (%d vs %d stmts) ROOT: cooked %s || recon %s"),
						*FnName, Verdict.RootCookedOrdinal, Verdict.RootReconOrdinal,
						CookedLossy.Num(), ReconLossy.Num(),
						Verdict.RootCooked.IsEmpty() ? TEXT("<no counterpart>") : *Verdict.RootCooked,
						Verdict.RootRecon.IsEmpty()  ? TEXT("<no counterpart>") : *Verdict.RootRecon);
				}
				else
				{
					// Classifier off or declined (cap/ambiguity) — fall back to the raw first-diff, exactly as before.
					const FString CookedS = CookedLossy.IsValidIndex(LossyDiff) ? CookedLossy[LossyDiff] : TEXT("<end of stream>");
					const FString ReconS  = ReconLossy.IsValidIndex(LossyDiff)  ? ReconLossy[LossyDiff]  : TEXT("<end of stream>");
					Out.FirstDrift = FString::Printf(TEXT("%s @ stmt %d (%d vs %d stmts): cooked %s || recon %s"),
						*FnName, LossyDiff, CookedLossy.Num(), ReconLossy.Num(), *CookedS, *ReconS);
				}
			}
#if MIF_KR_DEBUG
			UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[fidelity] DRIFT %s @ stmt %d"), *FnName, LossyDiff);
			for (int32 i = FMath::Max(0, LossyDiff - 2); i < FMath::Min(FMath::Max(CookedLossy.Num(), ReconLossy.Num()), LossyDiff + 3); ++i)
			{
				UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[fidelity]  %s %3d | %-90s | %s"),
					(i == LossyDiff) ? TEXT(">>") : TEXT("  "), i,
					CookedLossy.IsValidIndex(i) ? *CookedLossy[i] : TEXT("-"),
					ReconLossy.IsValidIndex(i)  ? *ReconLossy[i]  : TEXT("-"));
			}
#endif
		}

		// "flowstack=13;outparam=5" — sorted so the string is stable across runs and diffable between builds. This is
		// the spot-check handle: a reason whose count moves without a rule change is a red flag worth chasing.
		{
			TArray<FString> Reasons;
			IntentCounts.GetKeys(Reasons);
			Reasons.Sort();
			TArray<FString> Parts;
			for (const FString& R : Reasons) { Parts.Add(FString::Printf(TEXT("%s=%d"), *R, IntentCounts[R])); }
			Out.IntentTally = FString::Join(Parts, TEXT(";"));
		}
		return true;
	}
} // namespace MifKr::Fidelity

void MifKr_BindFidelityVerifier()
{
	GetBlueprintFidelityVerifier().BindStatic(&MifKr::Fidelity::VerifyBlueprint);
}

void MifKr_UnbindFidelityVerifier()
{
	GetBlueprintFidelityVerifier().Unbind();
}
