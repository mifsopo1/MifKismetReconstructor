// PHASE 3 — the decompiler back-end: driver (Run) + terminators + pass-2 pin-wiring.
// Added as members of the ported FKismetGraphDecompiler (needs its private patch-up maps).
// MVP slice ladder: getter (out-param literals) → member-getter (VariableGet) → setter → call.
// Control flow (branches/loops), delegates, macros, struct-field reads are DEFERRED.

#include "AssetGeneration/KismetGraphDecompiler.h"
#include "MifReconstructorDebug.h"

#include "EdGraphSchema_K2.h"
#include "EdGraphSchema_K2_Actions.h"
#include "EdGraph/EdGraph.h"
#include "EdGraph/EdGraphNode.h"
#include "EdGraph/EdGraphPin.h"
#include "EdGraphNode_Comment.h"   // EmitFailureComment now spawns a real, build-agnostic degrade-reason comment node
#include "K2Node_FunctionEntry.h"
#include "K2Node_FunctionResult.h"
#include "K2Node_VariableGet.h"
#include "K2Node_VariableSet.h"
#include "K2Node_Self.h"
#include "K2Node_BreakStruct.h"
#include "K2Node_MakeArray.h"
#include "K2Node_MakeContainer.h"
#include "K2Node_MakeSet.h"
#include "K2Node_MakeMap.h"
#include "K2Node_FormatText.h"
#include "K2Node_IfThenElse.h"
#include "K2Node_CallDelegate.h"
#include "K2Node_BaseMCDelegate.h"
#include "K2Node_AddDelegate.h"
#include "K2Node_RemoveDelegate.h"
#include "K2Node_ClearDelegate.h"
#include "K2Node_CreateDelegate.h"
#include "Engine/Blueprint.h"
#include "Kismet2/BlueprintEditorUtils.h"
#include "Kismet/KismetTextLibrary.h"
#include "Kismet/KismetMathLibrary.h"
#include "K2Node_DynamicCast.h"
#include "K2Node_GetDataTableRow.h"
#include "UObject/Interface.h"
#include "Misc/DefaultValueHelper.h"   // FDefaultValueHelper::ParseInt — the same parser the K2 schema validates with
#include "GameFramework/Actor.h"       // AActor — mirrors UK2Node_VariableSet::ShouldFlushDormancyOnSet's class test

// Link two data pins AND notify both nodes, so wildcard/container-typed nodes (Map_Add, MakeArray, …)
// propagate their concrete type from the connected pin. Raw MakeLinkTo alone leaves them "undetermined".
static void MifLinkData(UEdGraphPin* Source, UEdGraphPin* Dest)
{
	if (!Source || !Dest) return;
	// Plain link only. Type propagation (wildcard/container) is deferred to a single Phase-D pass in
	// WireAllPins so PinConnectionListChanged never reconstructs a node while we are still wiring it
	// (which would invalidate the exec-pin pointers captured in pass-1).
	Source->MakeLinkTo(Dest);
}

// The reconstructed local variable that stands in for an out-param named OutName. DDS2 writes out-params by
// assignment on each exec path; we mirror that as Set(local) nodes in the exec flow and a single Return that
// reads Get(local) — the graph's own dataflow then handles branches/pre-branch/shared writes correctly.
// NOTE: a NEUTRAL prefix (not the plugin/author name) — these locals appear inside the user's reconstructed
// graph, so they must read as reconstruction scaffolding, not carry any tool/author branding.
static FName MifLocalName(FName OutName)
{
	return FName(*(FString(TEXT("Local_")) + OutName.ToString()));
}

// Spawn a VariableGet/VariableSet bound to a function-scoped LOCAL variable (SetLocalMember, not a class member).
template<typename TNode>
static TNode* MifSpawnLocalVarNode(UEdGraph* Graph, UBlueprint* BP, FName LocalName, const FVector2D& Pos)
{
	const FGuid Guid = FBlueprintEditorUtils::FindLocalVariableGuidByName(BP, Graph, LocalName);
	return FEdGraphSchemaAction_K2NewNode::SpawnNode<TNode>(
		Graph, Pos, EK2NewNodeFlags::None,
		[&](TNode* N) { N->VariableReference.SetLocalMember(LocalName, Graph->GetName(), Guid); });
}

// The six conversions UK2Node_FormatText::ExpandNode re-inserts per arg-pin category (Int→Conv_IntToInt64, …). When a
// Format arg's value member-set IS one of these, the AUTHORED value is the conversion INPUT (RHS[0]) — unwrap it and let
// FormatText re-add the conv at compile. Any OTHER call producing the value is a real user node whose RETURN is the value.
static bool MifIsFormatTextArgConversion(const UFunction* F)
{
	if (!F) return false;
	const UClass* Owner = F->GetOwnerClass();
	const FString N = F->GetName();
	if (Owner == UKismetMathLibrary::StaticClass())
		return N == TEXT("Conv_IntToInt64") || N == TEXT("Conv_ByteToInt64");
	if (Owner == UKismetTextLibrary::StaticClass())
		return N == TEXT("Conv_BoolToText") || N == TEXT("Conv_NameToText")
			|| N == TEXT("Conv_StringToText") || N == TEXT("Conv_ObjectToText");
	return false;
}

// UBlueprintTypeConversions::Convert* — the float/double implicit-conversion thunks the KISMET COMPILER injects, never
// the user (UE::KismetCompiler::CastingUtils::InsertImplicitCastStatement emits a KCST_CallFunction to one of these for a
// container/struct float-precision mismatch). They are CustomThunk + BlueprintInternalUseOnly and their DECLARED
// signature is a PLACEHOLDER the compiler patches per call site (e.g. `static TMap<int,int> ConvertMapType(const
// TMap<int,int>&)`), so reconstructing one as a real call node yields literal "Map of Integers to Integers" pins that the
// schema rejects against every genuine link. Such a call is compiler scaffolding: ELIDE it and let the compiler
// re-insert the cast on recompile. Matched by owner-class NAME so this module needs no dependency on Engine's Internal/
// header (which is not on the plugin's include path).
static bool MifIsCompilerImplicitConversion(const UFunction* F)
{
	if (!F) return false;
	const UClass* Owner = F->GetOwnerClass();
	return Owner && Owner->GetName() == TEXT("BlueprintTypeConversions") && F->GetName().StartsWith(TEXT("Convert"));
}

// The out-param NAME a statement would write, or NAME_None if it is not an out-param write at all. SINGLE SOURCE OF
// TRUTH for the pre-scan (ScanOutParamAssignCounts) and the three pass-1 assignment sites, so the two can never
// disagree about WHICH statements assign an out-param.
//
// Deliberately a SUPERSET of the sites' guards: the sites additionally require the name to be a live FunctionResult
// input pin (ReturnInputPinByName), which the pre-scan CANNOT test — it runs before the Result pins are captured.
// Widening is the only safe direction:
//   * over-count → the name degrades to "keep the local", i.e. exactly today's branch-correct model;
//   * under-count → would wrongly collapse a BRANCHED out-param and lose a write. Never allowed.
// So a non-out-param name merely lands in a map entry nobody consults, and a local/member sharing an out-param's name
// can only inflate that out-param's count (a conservative keep). FKismetTerminal::EVarType has no out-param kind
// (Local/Default/Instanced only), so name+context-less is as tight as this can honestly get.
static FName MifOutParamWriteName(const TSharedPtr<FKismetCompiledStatement>& S)
{
	// The LHS shape every site requires: a valid, context-less, named write target (IsOutParamTerminal minus the
	// ReturnInputPinByName membership test). An empty name can never be a Result pin name, so excluding it here
	// cannot disagree with a site.
	if (!S.IsValid() || !S->LHS.IsValid() || S->LHS->Context.IsValid() || S->LHS->AssociatedVarProperty.IsEmpty())
		return NAME_None;

	using EType = ECompiledStatementType;
	switch (S->Type)
	{
	case EType::KCST_Assignment:           // site 1 — the DDS2 `Let(OutParam = value)` shape
	case EType::KCST_ObjectToBool:         // site 2 — `return Obj != None;`
	case EType::KCST_CastObjToInterface:   // site 3 — interface cast written into an out-param
	case EType::KCST_CastInterfaceToObj:
	case EType::KCST_CrossInterfaceCast:
		break;
	case EType::KCST_CallFunction:
		// The implicit-conversion elision block RETYPES this to KCST_Assignment during pass 1 and drops it into site 1.
		// The pre-scan runs BEFORE that mutation, so it must recognise the PRE-retype shape or it would UNDER-count
		// this write — the one direction that is unsafe.
		if (!(MifIsCompilerImplicitConversion(S->FunctionToCall) && S->RHS.Num() > 0 && S->RHS[0].IsValid()))
			return NAME_None;
		break;
	default:
		return NAME_None;
	}
	return FName(*S->LHS->AssociatedVarProperty);
}

void FKismetGraphDecompiler::ScanOutParamAssignCounts()
{
	OutParamAssignCount.Reset();
	for (const TSharedPtr<FKismetCompiledStatement>& S : CompiledStatements)
	{
		const FName N = MifOutParamWriteName(S);
		if (N != NAME_None) ++OutParamAssignCount.FindOrAdd(N);
	}
}

bool FKismetGraphDecompiler::Run(UFunction* SourceFunc,
	const TArray<TSharedPtr<FKismetCompiledStatement>>& Statements, UEdGraph* TargetGraph, UBlueprint* OwnerBP)
{
	Function = SourceFunc;
	EditorGraph = TargetGraph;
	OwnerBlueprint = OwnerBP;
	Initialize(Statements);                 // fills CompiledStatements
	CurrentStatementIndex = 0;

	FailureCount = 0; bDegraded = false; NodesCreated = 0; StatementsProcessed = 0; NextNodePosX = 320; FailureCommentPosY = 700;
	EntryNode = nullptr; ResultNode = nullptr; EntryThenPin = nullptr; ResultExecPin = nullptr;
	ParamOutputPinByName.Reset(); ReturnInputPinByName.Reset(); VariableGetterCache.Reset(); StatementIndexMap.Reset();
	OutParamAssignCount.Reset();
	StructMemberBreakCache.Reset(); SelfNodeCache = nullptr;   // per-graph: never reuse the previous graph's Self node
	FormatTextConsumedStmts.Reset(); FormatTextPlans.Reset(); DataTableRowStructByNode.Reset();
	IntermediateVariableHandles.Reset(); ExecPinPatchUpMap.Reset(); TerminalPatchUpMap.Reset(); IntermediateSnapshotByReader.Reset();
	NodeExecPinInputMap.Reset(); PassThroughTerminals.Reset(); CreateDelegatePatchUpMap.Reset();
	FlowStackPopTarget.Reset();

	K2Schema = GetMutableDefault<UEdGraphSchema_K2>();
	for (int32 i = 0; i < CompiledStatements.Num(); ++i)
	{
		if (CompiledStatements[i].IsValid()) StatementIndexMap.Add(CompiledStatements[i], i);
	}
	ResolveFlowStackTargets();   // must run after StatementIndexMap is populated
	ScanOutParamAssignCounts();  // MUST precede EstablishTerminators — it decides which out-params get a local

	EstablishTerminators();
	const bool bOk = RunGuardedBody();
	return bOk && !bDegraded;
}

void FKismetGraphDecompiler::ResolveFlowStackTargets()
{
	// Simulate the exec CFG from statement 0, maintaining the Kismet flow-stack. PushState pushes a continuation
	// target; EndOfThread pops+gotos it; EndOfThreadIfNot(cond) pops+gotos on the !cond branch and continues on
	// the cond branch. For structured (loop/return) bytecode the stack at each statement is deterministic, so a DFS
	// over branches with a (index, stack-depth, stack-top) visited guard terminates and records each pop's target.
	using EType = ECompiledStatementType;
	auto IdxOf = [&](const TSharedPtr<FKismetCompiledStatement>& S) -> int32
	{
		const int32* P = S.IsValid() ? StatementIndexMap.Find(S) : nullptr; return P ? *P : -1;
	};

	TSet<uint64> Visited;
	TArray<TPair<int32, TArray<int32>>> Work;   // (statement index, flow-stack of target indices)
	// Root at the ENTRY with the stack AS IT ACTUALLY IS there.
	//  - Function path: EntryStatementIndex is 0 and InitialFlowStack is empty — index 0 is the function's first
	//    statement, where the FFrame's stack genuinely IS empty. Unchanged behaviour, bit for bit.
	//  - Event path: the entry is the event's own entry statement within its slice, and the stack there is
	//    [ReturnAddress] whenever the ubergraph prologue pushed one, because execution passes THROUGH that push
	//    before the computed jump. Seeding empty would drop the return address and mis-resolve every EndOfThread
	//    that pops it. [B]
	Work.Add(TPair<int32, TArray<int32>>(EntryStatementIndex, InitialFlowStack));
	int32 Guard = 0;
	while (Work.Num() > 0 && Guard++ < 200000)
	{
		TPair<int32, TArray<int32>> Item = Work.Pop();
		int32 i = Item.Key;
		TArray<int32> Stack = MoveTemp(Item.Value);
		while (CompiledStatements.IsValidIndex(i))
		{
			const uint64 Key = ((uint64) (uint32) i) | ((uint64) Stack.Num() << 32) | ((uint64) (uint32) (Stack.Num() ? Stack.Last() : 0x7FFFFFFF) << 40);
			if (Visited.Contains(Key)) break;
			Visited.Add(Key);

			const TSharedPtr<FKismetCompiledStatement> S = CompiledStatements[i];
			if (!S.IsValid()) { ++i; continue; }
			const EType T = S->Type;

			if (T == EType::KCST_PushState)
			{
				const int32 Tgt = IdxOf(S->TargetLabel);
				if (Tgt >= 0) Stack.Add(Tgt);
				++i; continue;
			}
			if (T == EType::KCST_EndOfThread)
			{
				if (Stack.Num() == 0) break;   // empty stack → implicit return, exec ends
				const int32 Tgt = Stack.Pop();
				FlowStackPopTarget.Add(S, CompiledStatements.IsValidIndex(Tgt) ? CompiledStatements[Tgt] : nullptr);
				i = Tgt; continue;
			}
			if (T == EType::KCST_EndOfThreadIfNot)
			{
				if (Stack.Num() > 0)
				{
					const int32 Top = Stack.Last();
					FlowStackPopTarget.Add(S, CompiledStatements.IsValidIndex(Top) ? CompiledStatements[Top] : nullptr);
					TArray<int32> Popped = Stack; Popped.Pop();
					Work.Add(TPair<int32, TArray<int32>>(Top, MoveTemp(Popped)));   // !cond branch: pop + goto
				}
				++i; continue;   // cond branch: fall through
			}
			if (T == EType::KCST_UnconditionalGoto || T == EType::KCST_GotoReturn)
			{
				const int32 Tgt = IdxOf(S->TargetLabel);
				if (Tgt < 0) break;
				i = Tgt; continue;
			}
			if (T == EType::KCST_GotoIfNot || T == EType::KCST_GotoReturnIfNot)
			{
				const int32 Tgt = IdxOf(S->TargetLabel);
				if (Tgt >= 0) Work.Add(TPair<int32, TArray<int32>>(Tgt, Stack));   // !cond branch
				++i; continue;   // cond branch: fall through
			}
			if (T == EType::KCST_Return) break;
			// A computed goto's target is DYNAMIC (the ubergraph's event dispatch reads it from a parameter).
			// There is no static edge to follow and falling THROUGH it would silently continue into whatever
			// statement happens to be laid out next, with this walk's stack — a wrong-event, wrong-stack walk.
			// Slices never contain one (the slicer terminates a walk at a computed jump and counts the hit), so
			// this is belt-and-braces: if one ever appears, the walk stops instead of inventing an edge.
			if (T == EType::KCST_ComputedGoto) break;
			++i;   // linear statement — exec falls through to the next
		}
	}
}

// Pre-pass: find each FText::Format(InPattern, InArgs) call whose InArgs is a MakeStruct(FFormatArgumentData)[] chain,
// and plan its collapse into a single UK2Node_FormatText. Records the MakeArray + member-set constituents into a
// consumed-set (pass-1 skips them) and a plan keyed by the trigger Format call. (The chain can't compile as author
// nodes — FFormatArgumentData is BlueprintInternalUseOnly; only UK2Node_FormatText materializes it, at compile time.)
void FKismetGraphDecompiler::DetectFormatTextPatterns()
{
	UClass* TextLib = UKismetTextLibrary::StaticClass();
	for (int32 fi = 0; fi < CompiledStatements.Num(); ++fi)
	{
		const TSharedPtr<FKismetCompiledStatement> S = CompiledStatements[fi];
		if (!S.IsValid() || S->Type != ECompiledStatementType::KCST_CallFunction) continue;
		UFunction* F = S->FunctionToCall;
		if (!F || F->GetOwnerClass() != TextLib || F->GetName() != TEXT("Format")) continue;
		if (S->RHS.Num() < 2 || !S->RHS[1].IsValid()) continue;
		const TSharedPtr<FKismetTerminal> Pattern = S->RHS[0];
		const TSharedPtr<FKismetTerminal> ArgsArr = S->RHS[1];

		// nearest CreateArray that writes the InArgs (FFormatArgumentData[]) temp; none → not a MakeStruct Format
		TSharedPtr<FKismetCompiledStatement> ArrayStmt;
		for (int32 ai = 0; ai < fi; ++ai)
		{
			const TSharedPtr<FKismetCompiledStatement> A = CompiledStatements[ai];
			if (A.IsValid() && A->Type == ECompiledStatementType::KCST_CreateArray
				&& A->LHS.IsValid() && A->LHS->operator==(*ArgsArr)) ArrayStmt = A;
		}
		if (!ArrayStmt.IsValid()) continue;

		FFormatTextCollapsePlan P;
		P.ResultTerminal = S->LHS;
		P.PatternTerminal = Pattern;
		P.bPatternIsLiteral = Pattern.IsValid() && Pattern->bIsLiteral && Pattern->Type.PinCategory == UEdGraphSchema_K2::PC_Text;
		FormatTextConsumedStmts.Add(ArrayStmt.Get());

		// The cooked SetArray InArgs carries NO inline Values (ArrayStmt->RHS is empty — the FFormatArgumentData
		// elements are written IN PLACE), so drive arg collection from the member-write statements DIRECTLY, grouped by
		// struct-temp identity. (Iterating ArrayStmt->RHS was dead code → args were never captured → pins left unwired.)
		struct FArgAccum { FString Name; TSharedPtr<FKismetTerminal> Val; };
		TArray<FArgAccum> Accum;
		TMap<FKismetTerminalAsKeyType, int32> ByContext;   // struct-temp identity → arg index
		for (int32 mi = 0; mi < fi; ++mi)
		{
			const TSharedPtr<FKismetCompiledStatement> M = CompiledStatements[mi];
			if (!M.IsValid() || FormatTextConsumedStmts.Contains(M.Get())) continue;   // skip a prior Format's members
			if (M->Type != ECompiledStatementType::KCST_Assignment && M->Type != ECompiledStatementType::KCST_CallFunction) continue;
			if (!M->LHS.IsValid() || !M->LHS->Context.IsValid()) continue;
			if (M->LHS->Context->ContextType != FKismetTerminal::EContextType_Struct) continue;
			if (!M->LHS->Context->AssociatedVarProperty.StartsWith(TEXT("K2Node_MakeStruct"))) continue;   // an FFormatArgumentData MakeStruct temp
			const FString Mem = M->LHS->AssociatedVarProperty;
			if (Mem != TEXT("ArgumentName") && Mem != TEXT("ArgumentValueType") && Mem != TEXT("ArgumentValue")
				&& Mem != TEXT("ArgumentValueInt") && Mem != TEXT("ArgumentValueFloat")
				&& Mem != TEXT("ArgumentValueDouble") && Mem != TEXT("ArgumentValueGender")) continue;

			FKismetTerminalAsKeyType Key(M->LHS->Context);
			int32 Idx; if (int32* Slot = ByContext.Find(Key)) Idx = *Slot;
			else { Idx = Accum.AddDefaulted(); ByContext.Add(Key, Idx); }
			FArgAccum& A = Accum[Idx];

			if (Mem == TEXT("ArgumentName"))
			{
				if (M->RHS.Num() && M->RHS[0].IsValid())
					A.Name = (M->RHS[0]->Type.PinCategory == UEdGraphSchema_K2::PC_Text)
						? M->RHS[0]->TextLiteral.ToString() : M->RHS[0]->StringLiteral;
				FormatTextConsumedStmts.Add(M.Get());
			}
			else if (Mem == TEXT("ArgumentValueType"))
			{
				FormatTextConsumedStmts.Add(M.Get());
			}
			else   // ArgumentValue / ArgumentValueInt / ArgumentValueFloat / ArgumentValueDouble / ArgumentValueGender
			{
				if (M->Type == ECompiledStatementType::KCST_Assignment)
				{
					if (M->RHS.Num() && M->RHS[0].IsValid()) A.Val = M->RHS[0];   // direct value terminal
					FormatTextConsumedStmts.Add(M.Get());
				}
				else if (MifIsFormatTextArgConversion(M->FunctionToCall))
				{
					if (M->RHS.Num() && M->RHS[0].IsValid()) A.Val = M->RHS[0];   // unwrap the conversion INPUT
					FormatTextConsumedStmts.Add(M.Get());
				}
				else
				{
					// a real value-producing CALL written into the member: value is its RETURN. Key on the member
					// terminal (CreateFunctionCallNode registers IVH[LHS]=ReturnValue) and DO NOT consume M.
					A.Val = M->LHS;
				}
			}
		}
		for (const FArgAccum& A : Accum)
			P.Args.Add(TPair<FString, TSharedPtr<FKismetTerminal>>(A.Name, A.Val));
		FormatTextPlans.Add(S.Get(), P);
	}
}

// Emit a planned Format as ONE pure UK2Node_FormatText: set the Format text literal (auto-creates an argument pin per
// {token}), wire each arg value to its named pin, and register the Result output as the Format call's producer.
UEdGraphNode* FKismetGraphDecompiler::EmitFormatTextNode(const FFormatTextCollapsePlan& P)
{
	UK2Node_FormatText* N = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_FormatText>(
		EditorGraph, FVector2D(NextNodePosX, 200.0), EK2NewNodeFlags::None,
		[](UK2Node_FormatText* Node){});
	if (!N) return EmitFailureComment(TEXT("FormatText spawn failed (deferred)"));

	// Literal pattern → set the Format text: TrySetDefaultText fires PinDefaultValueChanged, which auto-creates one
	// wildcard argument pin per unique {token}. (A non-literal/computed pattern is left at default; args log-degrade.)
	if (P.bPatternIsLiteral && P.PatternTerminal.IsValid())
	{
		if (UEdGraphPin* FP = N->GetFormatPin())
			K2Schema->TrySetDefaultText(*FP, P.PatternTerminal->TextLiteral, /*bMarkAsModified*/ false);
	}
	else EmitFailureComment(TEXT("FormatText non-literal pattern → pin left default (deferred)"));

	for (int32 i = 0; i < P.Args.Num(); ++i)
	{
		const TSharedPtr<FKismetTerminal>& V = P.Args[i].Value;
		UEdGraphPin* Arg = P.Args[i].Key.IsEmpty() ? nullptr : N->FindArgumentPin(FName(*P.Args[i].Key));
		if (!Arg && P.bPatternIsLiteral && i < N->GetArgumentCount())   // token order == array order fallback
			Arg = N->FindArgumentPin(FName(*N->GetArgumentName(i).ToString()));
		if (!Arg) { EmitFailureComment(FString::Printf(TEXT("FormatText arg[%d] '%s' pin missing (deferred)"), i, *P.Args[i].Key)); continue; }
		if (V.IsValid()) RecordTerminalRead(Arg, V);
		else K2Schema->TrySetDefaultText(*Arg, FText::GetEmpty(), /*bMarkAsModified*/ false);   // typed empty-text, not a lingering wildcard
	}

	if (UEdGraphPin* R = N->FindPin(TEXT("Result"), EGPD_Output))
		if (P.ResultTerminal.IsValid()) IntermediateVariableHandles.Add(FKismetTerminalAsKeyType(P.ResultTerminal), R);
	return N;
}

bool FKismetGraphDecompiler::RunGuardedBody()
{
	// ---------------- PASS 1: spawn nodes ----------------
	// Out-param model (see EstablishTerminators). An out-param assigned 2+ times is reconstructed as a function-scoped
	// LOCAL variable: each `Let OutParam = X` becomes a Set(local) node THREADED INTO THE EXEC FLOW and the single
	// Return reads Get(local) — branch-correct by construction (no pending accumulation, no multi-return), at the cost
	// of one extra bytecode statement. An out-param assigned EXACTLY ONCE (ScanOutParamAssignCounts) is COLLAPSED: no
	// local, no Set/Get — the value feeds the Return pin directly, which recompiles byte-identical to the cooked
	// `Let(OutParam = value)`. With one writer there is no branch for two writes to collide on, so the local that
	// bought branch-correctness buys nothing.
	DetectFormatTextPatterns();   // pre-pass: plan FText::Format collapses (constituents precede the call in statement order)
	while (CurrentStatementIndex < CompiledStatements.Num())
	{
		TSharedPtr<FKismetCompiledStatement> S = PeekStatement();
		if (!S.IsValid()) { PopStatement(); continue; }
		++StatementsProcessed;

		if (S->Type == ECompiledStatementType::KCST_Nop) { PopStatement(); continue; }

		// FText::Format collapse — drop the MakeStruct/MakeArray constituents and emit the trigger call as one
		// UK2Node_FormatText (a hand-built MakeStruct(FFormatArgumentData) can't compile: BlueprintInternalUseOnly).
		if (FormatTextConsumedStmts.Contains(S.Get())) { PopStatement(); continue; }
		if (const FFormatTextCollapsePlan* Plan = FormatTextPlans.Find(S.Get()))
		{
			UEdGraphNode* FN = EmitFormatTextNode(*Plan);
			PopStatement();
			if (FN) { ++NodesCreated; FN->NodePosX = NextNodePosX; NextNodePosX += 320; }
			continue;
		}

		if (S->Type == ECompiledStatementType::KCST_Return)
		{
			HandleReturnStatement(S);
			PopStatement();
			continue;
		}

		// Exec-flow markers that need no node — pass-2 ResolveExecTarget threads through them.
		// KCST_GotoReturn → the single Return; KCST_PushState → threaded through; KCST_EndOfThread → its flow-stack
		// pop target (resolved in ResolveExecTarget via FlowStackPopTarget). (EndOfThreadIfNot is a branch, above.)
		if (S->Type == ECompiledStatementType::KCST_UnconditionalGoto ||
			S->Type == ECompiledStatementType::KCST_GotoReturn ||
			S->Type == ECompiledStatementType::KCST_PushState ||
			S->Type == ECompiledStatementType::KCST_EndOfThread ||
			S->Type == ECompiledStatementType::KCST_ComputedGoto)
		{
			PopStatement();
			continue;
		}

		// Conditional branch → UK2Node_IfThenElse. GotoIfNot: if(!cond) goto Target; else fall through.
		// EndOfThreadIfNot: if(!cond) pop the flow-stack + goto that target (loop-back / structured return); else fall through.
		if (S->Type == ECompiledStatementType::KCST_GotoIfNot ||
			S->Type == ECompiledStatementType::KCST_GotoReturnIfNot ||
			S->Type == ECompiledStatementType::KCST_EndOfThreadIfNot)
		{
			UK2Node_IfThenElse* Branch = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_IfThenElse>(
				EditorGraph, EditorGraph->GetGoodPlaceForNewNode(), EK2NewNodeFlags::None);
			PopStatement();
			if (Branch)
			{
				++NodesCreated; Branch->NodePosX = NextNodePosX; NextNodePosX += 320;
				if (UEdGraphPin* ExecIn = Branch->GetExecPin()) NodeExecPinInputMap.Add(S, ExecIn);
				if (UEdGraphPin* CondPin = Branch->GetConditionPin())
					if (S->LHS.IsValid()) RecordTerminalRead(CondPin, S->LHS);
				if (UEdGraphPin* ThenPin = Branch->GetThenPin())   // condition TRUE → fall through to the next statement
				{
					const TSharedPtr<FKismetCompiledStatement> FallThrough = PeekNextValidStatement(0);
					if (FallThrough.IsValid()) ExecPinPatchUpMap.Add(ThenPin, FallThrough);
				}
				if (UEdGraphPin* ElsePin = Branch->GetElsePin())   // condition FALSE → the jump target
				{
					// EndOfThreadIfNot jumps to its flow-stack pop target; Goto*IfNot to its TargetLabel.
					const TSharedPtr<FKismetCompiledStatement>* PopTgt =
						(S->Type == ECompiledStatementType::KCST_EndOfThreadIfNot) ? FlowStackPopTarget.Find(S) : nullptr;
					const TSharedPtr<FKismetCompiledStatement> ElseTarget = PopTgt ? *PopTgt : S->TargetLabel;
					if (ElseTarget.IsValid()) ExecPinPatchUpMap.Add(ElsePin, ElseTarget);
				}
			}
			continue;
		}

		// Multicast delegate broadcast → UK2Node_CallDelegate.
		if (S->Type == ECompiledStatementType::KCST_CallDelegate)
		{
			const TSharedPtr<FKismetTerminal> DelegateTerm = S->FunctionContext;
			PopStatement();
			UStruct* CtxStruct = nullptr;
			if (DelegateTerm.IsValid())
			{
				CtxStruct = (DelegateTerm->VarType == FKismetTerminal::EVarType_Instanced && (!DelegateTerm->Context.IsValid() || IsSelfTerminal(DelegateTerm->Context)))
					? (UStruct*) (OwnerBlueprint ? OwnerBlueprint->SkeletonGeneratedClass : nullptr)
					: ResolveContextTerminalType(DelegateTerm->Context);
			}
			UClass* CtxClass = Cast<UClass>(CtxStruct);
			FMulticastDelegateProperty* DelegateProp = (CtxClass && DelegateTerm.IsValid())
				? CastField<FMulticastDelegateProperty>(CtxClass->FindPropertyByName(FName(*DelegateTerm->AssociatedVarProperty)))
				: nullptr;
			if (DelegateProp)
			{
				const bool bSelf = !DelegateTerm->Context.IsValid() || IsSelfTerminal(DelegateTerm->Context);
				UK2Node_CallDelegate* CallDel = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_CallDelegate>(
					EditorGraph, EditorGraph->GetGoodPlaceForNewNode(), EK2NewNodeFlags::None,
					[&](UK2Node_CallDelegate* N){ N->SetFromProperty(DelegateProp, bSelf, CtxClass); });
				if (CallDel)
				{
					++NodesCreated; CallDel->NodePosX = NextNodePosX; NextNodePosX += 320;
					if (UEdGraphPin* ExecIn = CallDel->FindPin(UEdGraphSchema_K2::PN_Execute, EGPD_Input)) NodeExecPinInputMap.Add(S, ExecIn);
					if (UEdGraphPin* ThenPin = CallDel->FindPin(UEdGraphSchema_K2::PN_Then, EGPD_Output))
					{
						const TSharedPtr<FKismetCompiledStatement> Succ = PeekNextValidStatement(0);
						if (Succ.IsValid()) ExecPinPatchUpMap.Add(ThenPin, Succ);
					}
					// Broadcast params → the signature's param pins (skips the deferred no-param case cleanly).
					if (DelegateProp->SignatureFunction)
					{
						int32 PArg = 0;
						for (TFieldIterator<FProperty> PIt(DelegateProp->SignatureFunction); PIt && (PIt->PropertyFlags & CPF_Parm); ++PIt)
						{
							if (PIt->HasAnyPropertyFlags(CPF_ReturnParm)) continue;
							const TSharedPtr<FKismetTerminal> Arg = S->RHS.IsValidIndex(PArg) ? S->RHS[PArg] : nullptr;
							++PArg;
							if (Arg.IsValid())
								if (UEdGraphPin* InPin = CallDel->FindPin(PIt->GetFName(), EGPD_Input))
									RecordTerminalRead(InPin, Arg);
						}
					}
				}
			}
			else EmitFailureComment(TEXT("delegate broadcast property unresolved (deferred)"));
			continue;
		}

		// --- DELEGATE-BIND family (Bind Event to Event Dispatcher) --------------------------------------------
		// "Bind Event to Dispatcher" compiles to EX_BindDelegate (create a delegate value bound to a function) then
		// EX_AddMulticastDelegate (register it). These types had NO whitelist/handler, so every one degraded the whole
		// event at the unsupported gate — the single biggest event-reconstruction failure bucket (measured on a bridge-
		// authored testbed BP_DelegateTest). BindDelegate emits a PURE UK2Node_CreateDelegate and PUBLISHES its output
		// pin under the delegate temp (S->LHS) via IntermediateVariableHandles — the exact mechanism ObjectToBool's
		// IsValid output uses — so the following Add/Remove resolves its delegate input to it.

		// BindDelegate: LHS = delegate temp; RHS[0] = function-name literal (PC_Name); RHS[1] = target object.
		if (S->Type == ECompiledStatementType::KCST_BindDelegate)
		{
			PopStatement();
			if (!S->LHS.IsValid() || !S->RHS.IsValidIndex(0) || !S->RHS[0].IsValid() || !S->RHS[0]->bIsLiteral)
			{
				EmitFailureComment(TEXT("BindDelegate malformed (deferred)"));
				continue;
			}
			UK2Node_CreateDelegate* CreateDel = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_CreateDelegate>(
				EditorGraph, EditorGraph->GetGoodPlaceForNewNode(), EK2NewNodeFlags::None,
				[](UK2Node_CreateDelegate*){});
			if (!CreateDel)
			{
				EmitFailureComment(TEXT("CreateDelegate spawn failed"));
				continue;
			}
			++NodesCreated; CreateDel->NodePosX = NextNodePosX; NextNodePosX += 320;
			CreateDel->SetFunction(FName(*S->RHS[0]->StringLiteral));
			// target object → CreateDelegate's object input (pure node — no exec pins).
			if (S->RHS.IsValidIndex(1) && S->RHS[1].IsValid())
				if (UEdGraphPin* ObjPin = CreateDel->GetObjectInPin())
					RecordTerminalRead(ObjPin, S->RHS[1]);
			// publish the delegate output so a following Add/Remove links its delegate input to it.
			if (UEdGraphPin* OutPin = CreateDel->GetDelegateOutPin())
				IntermediateVariableHandles.Add(FKismetTerminalAsKeyType(S->LHS), OutPin);
			continue;
		}

		// Add / Remove a delegate to/from a multicast (event dispatcher): LHS = the multicast property, RHS[0] = the
		// delegate temp published by BindDelegate above.
		if (S->Type == ECompiledStatementType::KCST_AddMulticastDelegate ||
			S->Type == ECompiledStatementType::KCST_RemoveMulticastDelegate)
		{
			const bool bAdd = (S->Type == ECompiledStatementType::KCST_AddMulticastDelegate);
			const TSharedPtr<FKismetTerminal> McTerm = S->LHS;
			const TSharedPtr<FKismetTerminal> DelTerm = S->RHS.IsValidIndex(0) ? S->RHS[0] : nullptr;
			PopStatement();
			UStruct* CtxStruct = nullptr;
			if (McTerm.IsValid())
			{
				CtxStruct = (McTerm->VarType == FKismetTerminal::EVarType_Instanced && (!McTerm->Context.IsValid() || IsSelfTerminal(McTerm->Context)))
					? (UStruct*) (OwnerBlueprint ? OwnerBlueprint->SkeletonGeneratedClass : nullptr)
					: ResolveContextTerminalType(McTerm->Context);
			}
			UClass* CtxClass = Cast<UClass>(CtxStruct);
			FMulticastDelegateProperty* DelegateProp = (CtxClass && McTerm.IsValid())
				? CastField<FMulticastDelegateProperty>(CtxClass->FindPropertyByName(FName(*McTerm->AssociatedVarProperty)))
				: nullptr;
			if (!DelegateProp)
			{
				EmitFailureComment(bAdd ? TEXT("AddMulticastDelegate property unresolved (deferred)")
										: TEXT("RemoveMulticastDelegate property unresolved (deferred)"));
				continue;
			}
			const bool bSelf = !McTerm->Context.IsValid() || IsSelfTerminal(McTerm->Context);
			// CONSERVATIVE (no hard fails): reconstruct ONLY a USER event-dispatcher bind — self-context AND a
			// BlueprintAssignable multicast property. Compiler-generated binds (async-proxy callbacks like
			// PlayMontageCallbackProxy, Timeline track delegates that are not blueprint-visible, non-self internal binds)
			// MUST degrade, not become manual nodes: they otherwise fail COMPILE ("Target must have a connection" /
			// "not blueprint visible") — a hard fail, strictly worse than the soft degrade they replace. Also destroy the
			// orphan UK2Node_CreateDelegate the paired BindDelegate already spawned, so degrading leaves a clean stub.
			if (!bSelf || !DelegateProp->HasAnyPropertyFlags(CPF_BlueprintAssignable))
			{
				if (DelTerm.IsValid())
					if (UEdGraphPin** OutPin = IntermediateVariableHandles.Find(FKismetTerminalAsKeyType(DelTerm)))
						if (*OutPin && (*OutPin)->GetOwningNodeUnchecked())
						{
							(*OutPin)->GetOwningNode()->DestroyNode();
							if (NodesCreated > 0) { --NodesCreated; }
							IntermediateVariableHandles.Remove(FKismetTerminalAsKeyType(DelTerm));
						}
				EmitFailureComment(TEXT("delegate add/remove is non-self or non-assignable (compiler-generated) — deferred"));
				continue;
			}
			// ADVERSARIAL GUARD (never silently wrong): the delegate being added MUST have been published by a
			// preceding BindDelegate. If it is not in IntermediateVariableHandles, wiring would leave the delegate input
			// dangling → a node that recompiles to "add/remove nothing". Hard-degrade rather than emit a half-wired bind.
			if (!DelTerm.IsValid() || !IntermediateVariableHandles.Contains(FKismetTerminalAsKeyType(DelTerm)))
			{
				EmitFailureComment(TEXT("delegate bind source unresolved for Add/Remove multicast (deferred)"));
				continue;
			}
			UK2Node_BaseMCDelegate* Node = bAdd
				? (UK2Node_BaseMCDelegate*) FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_AddDelegate>(
					EditorGraph, EditorGraph->GetGoodPlaceForNewNode(), EK2NewNodeFlags::None,
					[&](UK2Node_AddDelegate* N){ N->SetFromProperty(DelegateProp, bSelf, CtxClass); })
				: (UK2Node_BaseMCDelegate*) FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_RemoveDelegate>(
					EditorGraph, EditorGraph->GetGoodPlaceForNewNode(), EK2NewNodeFlags::None,
					[&](UK2Node_RemoveDelegate* N){ N->SetFromProperty(DelegateProp, bSelf, CtxClass); });
			if (!Node)
			{
				EmitFailureComment(TEXT("Add/Remove multicast delegate spawn failed"));
				continue;
			}
			++NodesCreated; Node->NodePosX = NextNodePosX; NextNodePosX += 320;
			if (UEdGraphPin* ExecIn = Node->FindPin(UEdGraphSchema_K2::PN_Execute, EGPD_Input)) NodeExecPinInputMap.Add(S, ExecIn);
			if (UEdGraphPin* ThenPin = Node->FindPin(UEdGraphSchema_K2::PN_Then, EGPD_Output))
			{
				const TSharedPtr<FKismetCompiledStatement> Succ = PeekNextValidStatement(0);
				if (Succ.IsValid()) ExecPinPatchUpMap.Add(ThenPin, Succ);
			}
			if (UEdGraphPin* DelPin = Node->GetDelegatePin())
				RecordTerminalRead(DelPin, DelTerm);
			continue;
		}

		// Clear all bindings on a multicast (event dispatcher): LHS = the multicast property; no delegate operand.
		if (S->Type == ECompiledStatementType::KCST_ClearMulticastDelegate)
		{
			const TSharedPtr<FKismetTerminal> McTerm = S->LHS;
			PopStatement();
			UStruct* CtxStruct = nullptr;
			if (McTerm.IsValid())
			{
				CtxStruct = (McTerm->VarType == FKismetTerminal::EVarType_Instanced && (!McTerm->Context.IsValid() || IsSelfTerminal(McTerm->Context)))
					? (UStruct*) (OwnerBlueprint ? OwnerBlueprint->SkeletonGeneratedClass : nullptr)
					: ResolveContextTerminalType(McTerm->Context);
			}
			UClass* CtxClass = Cast<UClass>(CtxStruct);
			FMulticastDelegateProperty* DelegateProp = (CtxClass && McTerm.IsValid())
				? CastField<FMulticastDelegateProperty>(CtxClass->FindPropertyByName(FName(*McTerm->AssociatedVarProperty)))
				: nullptr;
			if (!DelegateProp)
			{
				EmitFailureComment(TEXT("ClearMulticastDelegate property unresolved (deferred)"));
				continue;
			}
			const bool bSelf = !McTerm->Context.IsValid() || IsSelfTerminal(McTerm->Context);
			if (!bSelf || !DelegateProp->HasAnyPropertyFlags(CPF_BlueprintAssignable))
			{
				EmitFailureComment(TEXT("delegate clear is non-self or non-assignable (compiler-generated) — deferred"));
				continue;
			}
			UK2Node_ClearDelegate* Node = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_ClearDelegate>(
				EditorGraph, EditorGraph->GetGoodPlaceForNewNode(), EK2NewNodeFlags::None,
				[&](UK2Node_ClearDelegate* N){ N->SetFromProperty(DelegateProp, bSelf, CtxClass); });
			if (!Node)
			{
				EmitFailureComment(TEXT("ClearMulticastDelegate spawn failed"));
				continue;
			}
			++NodesCreated; Node->NodePosX = NextNodePosX; NextNodePosX += 320;
			if (UEdGraphPin* ExecIn = Node->FindPin(UEdGraphSchema_K2::PN_Execute, EGPD_Input)) NodeExecPinInputMap.Add(S, ExecIn);
			if (UEdGraphPin* ThenPin = Node->FindPin(UEdGraphSchema_K2::PN_Then, EGPD_Output))
			{
				const TSharedPtr<FKismetCompiledStatement> Succ = PeekNextValidStatement(0);
				if (Succ.IsValid()) ExecPinPatchUpMap.Add(ThenPin, Succ);
			}
			continue;
		}

		// REPLICATED-SET IDIOM, leading half. FKCHandler_VariableSet::Transform AUTO-GENERATES a FlushNetDormancy call
		// node in FRONT of a Set on a CPF_Net property of an AActor (final exec order: FlushNetDormancy → Set →
		// MarkPropertyDirtyFromRepIndex → RepNotify). So the cooked FlushNetDormancy is compiler scaffolding that the
		// reconstructed UK2Node_VariableSet RE-EMITS by itself: reconstructing it as its own call node too emits it
		// TWICE — the observed EndMeeting/StartMeeting drift. Consume it here; the Set's TRAILING companions are
		// consumed in CreateVariableSetNode, where the real node can be asked its own predicates directly.
		//
		// Requiring the IMMEDIATELY-next statement to be the rep-Set keeps the gate narrow AND handles a USER-authored
		// FlushNetDormancy stacked in front (cooked: Flush(user), Flush(auto), Let): the first sees another Flush next,
		// not the Set, so only the compiler's own is dropped. No node is created and no NodeExecPinInputMap entry is
		// recorded, so pass-2's ResolveExecTarget threads any jump aimed at this statement forward to the Set node —
		// which re-emits the Flush first. Exec order is preserved.
		if (S->Type == ECompiledStatementType::KCST_CallFunction && S->FunctionToCall
			&& S->FunctionToCall->GetFName() == TEXT("FlushNetDormancy")
			&& WillRepSetReemitFlushNetDormancy(PeekStatement(1)))
		{
#if MIF_KR_DEBUG
			const TSharedPtr<FKismetCompiledStatement> RepSet = PeekStatement(1);
			UE_LOG(LogMifKismetReconstructor, Warning,
				TEXT("[rep-set] consumed compiler-generated FlushNetDormancy before Set '%s' (the Set node re-emits it)"),
				RepSet.IsValid() && RepSet->LHS.IsValid() ? *RepSet->LHS->AssociatedVarProperty : TEXT("?"));
#endif
			PopStatement();
			continue;
		}

		// Compiler-inserted implicit float/double conversion (UBlueprintTypeConversions::Convert*) → ELIDE to a
		// pass-through. The cooked bytecode carries `tmp = ConvertMapType(row.PresetConfig); this.CurPresetSettings = tmp;`
		// because the ORIGINAL graph was just `row.PresetConfig → Set CurPresetSettings` and the compiler injected the
		// cast. Rebuilding the call node reproduces its PLACEHOLDER TMap<int,int> signature and every link fails; dropping
		// it restores the authored dataflow and the compiler re-inserts the cast itself on recompile. If the conversion
		// writes straight into an out-param, retype to KCST_Assignment so the out-param Set(local) block directly below
		// handles it (value ← the conversion's INPUT).
		if (S->Type == ECompiledStatementType::KCST_CallFunction && MifIsCompilerImplicitConversion(S->FunctionToCall)
			&& S->LHS.IsValid() && S->RHS.Num() > 0 && S->RHS[0].IsValid())
		{
			if (IsOutParamTerminal(S->LHS))
			{
				S->Type = ECompiledStatementType::KCST_Assignment;   // fall through to the out-param block below
			}
			else
			{
				PassThroughTerminals.Add(FKismetTerminalAsKeyType(S->LHS), S->RHS[0]);
				PopStatement();
				continue;
			}
		}

		// Out-param write (assignment model). MULTI-ASSIGN → Set(local) node threaded into the exec flow (value ← RHS);
		// the single Return reads Get(local), so branches, pre-branch writes, and shared writes all resolve via graph
		// dataflow. SINGLE-ASSIGN → collapsed to a direct Return-pin feed (see below).
		if (S->Type == ECompiledStatementType::KCST_Assignment && S->LHS.IsValid() && !S->LHS->Context.IsValid()
			&& ReturnInputPinByName.Contains(FName(*S->LHS->AssociatedVarProperty)))
		{
			const FName OutName(*S->LHS->AssociatedVarProperty);
			// COLLAPSE (assigned exactly once ⇒ no branch can collide on the Return pin): no local, no Set node. The
			// RHS value feeds the FunctionResult input pin directly — the pre-local design — so this recompiles to the
			// cooked `Let(OutParam = value)` byte-for-byte. The statement becomes PURE DATAFLOW: no NodeExecPinInputMap
			// / ExecPinPatchUpMap entry, so exec threads straight from the previous statement to the next.
			// Gated on the assign count ALONE — the very test EstablishTerminators used to skip the local — so the two
			// can never disagree and strand a Set node on a local that was never created.
			if (IsSingleAssignOutParam(OutName))
			{
				PopStatement();
				// RecordTerminalRead (inside) runs HERE in pass 1, never inside WireAllPins' Phase B range-for over
				// TerminalPatchUpMap. TryHandleOutParamAssignment cannot fail under this guard (it re-tests exactly
				// the conditions already established above); the comment is the soft-degrade if that ever changes.
				if (!(S->RHS.Num() > 0 && S->RHS[0].IsValid()) || !TryHandleOutParamAssignment(S))
					EmitFailureComment(TEXT("single-assign out-param has no usable RHS → Return pin left at its default"));
				continue;
			}
			const FName Local = MifLocalName(OutName);
			PopStatement();
			UK2Node_VariableSet* Set = MifSpawnLocalVarNode<UK2Node_VariableSet>(
				EditorGraph, OwnerBlueprint, Local, FVector2D(NextNodePosX, 0.0));
			if (Set)
			{
				++NodesCreated; Set->NodePosX = NextNodePosX; NextNodePosX += 320;
				if (UEdGraphPin* ExecIn = Set->FindPin(UEdGraphSchema_K2::PN_Execute, EGPD_Input)) NodeExecPinInputMap.Add(S, ExecIn);
				if (UEdGraphPin* ThenPin = Set->FindPin(UEdGraphSchema_K2::PN_Then, EGPD_Output))
				{
					const TSharedPtr<FKismetCompiledStatement> Succ = PeekNextValidStatement(0);
					if (Succ.IsValid()) ExecPinPatchUpMap.Add(ThenPin, Succ);
				}
				if (S->RHS.Num() > 0 && S->RHS[0].IsValid())
					if (UEdGraphPin* ValPin = Set->FindPin(Local, EGPD_Input)) RecordTerminalRead(ValPin, S->RHS[0]);
			}
			else EmitFailureComment(TEXT("out-param local Set node spawn failed"));
			continue;
		}

		// Standalone object/interface → bool (KCST_ObjectToBool NOT consumed by a paired DynamicCast) → a pure
		// UKismetSystemLibrary::IsValid call (yields a real bool pin; the K2 schema has no object→bool autocast).
		// Popped+continued BEFORE the support gate, so no "unsupported statement type" spam / FailureCount collapse.
		if (S->Type == ECompiledStatementType::KCST_ObjectToBool)
		{
			if (!S->RHS.Num() || !S->RHS[0].IsValid() || !S->LHS.IsValid())
			{
				EmitFailureComment(TEXT("ObjectToBool malformed (deferred)")); PopStatement(); continue;
			}
			UEdGraphPin* BoolOut = EmitObjectIsValidNode(S->RHS[0]);
			if (!BoolOut) { EmitFailureComment(TEXT("ObjectToBool IsValid unavailable (deferred)")); PopStatement(); continue; }
			if (IsOutParamTerminal(S->LHS))                                   // e.g. `return Obj != None;`
			{
				const FName OutName(*S->LHS->AssociatedVarProperty);
				// COLLAPSE (single-assign): IsValid's bool output goes straight to the FunctionResult input pin; the
				// statement becomes pure dataflow (no exec-map entry) exactly as at the KCST_Assignment site.
				// NOTE: the VALUE here is the emitted IsValid node's OUTPUT PIN, not S->RHS[0] — RHS[0] is the OBJECT
				// being tested. So this links the pin; recording RHS[0] against the Return pin would deliver the
				// object where a bool belongs. BoolOut is non-null: the !BoolOut case already continued out above.
				if (IsSingleAssignOutParam(OutName))
				{
					PopStatement();
					if (UEdGraphPin** RetPin = ReturnInputPinByName.Find(OutName)) MifLinkData(BoolOut, *RetPin);
					else EmitFailureComment(TEXT("ObjectToBool out-param collapse: Return pin missing"));
					continue;
				}
				const FName Local = MifLocalName(OutName);
				PopStatement();
				UK2Node_VariableSet* Set = MifSpawnLocalVarNode<UK2Node_VariableSet>(EditorGraph, OwnerBlueprint, Local, FVector2D(NextNodePosX, 0.0));
				if (Set)
				{
					++NodesCreated; Set->NodePosX = NextNodePosX; NextNodePosX += 320;
					if (UEdGraphPin* ExecIn = Set->FindPin(UEdGraphSchema_K2::PN_Execute, EGPD_Input)) NodeExecPinInputMap.Add(S, ExecIn);
					if (UEdGraphPin* ThenPin = Set->FindPin(UEdGraphSchema_K2::PN_Then, EGPD_Output))
					{
						const TSharedPtr<FKismetCompiledStatement> Succ = PeekNextValidStatement(0);
						if (Succ.IsValid()) ExecPinPatchUpMap.Add(ThenPin, Succ);
					}
					if (UEdGraphPin* ValPin = Set->FindPin(Local, EGPD_Input)) MifLinkData(BoolOut, ValPin);
				}
				else EmitFailureComment(TEXT("ObjectToBool out-param Set spawn failed"));
				continue;
			}
			IntermediateVariableHandles.Add(FKismetTerminalAsKeyType(S->LHS), BoolOut);   // intermediate / branch condition
			PopStatement();
			continue;
		}

		// Implicit obj<->interface conversion → a real (pure) UK2Node_DynamicCast to the interface/object TargetType.
		// A raw object wired into a strict interface Target pin is REJECTED by the schema (only interface→object
		// autocasts), so the old pass-through left an incompatible link. Falls back to pass-through if the class is unresolved.
		if (S->Type == ECompiledStatementType::KCST_CastObjToInterface ||
			S->Type == ECompiledStatementType::KCST_CastInterfaceToObj ||
			S->Type == ECompiledStatementType::KCST_CrossInterfaceCast)
		{
			// IMPURE interface-cast idiom (DDS2): Cast* ; ObjectToBool(ifaceTemp!=None) ; GotoIfNot → fail — byte-for-byte
			// the shape CreateCastNode already reconstructs for OBJECT casts. Route it through CreateCastNode → ONE impure
			// UK2Node_DynamicCast (interface TargetType ⇒ PC_Interface result; Cast-Succeeded/Failed exec ARE the branch);
			// CreateCastNode CONSUMES the paired ObjectToBool + the GotoIfNot, so the standalone ObjectToBool→IsValid block
			// never sees it (no spurious IsValid, no interface→object type error). Gate on the ObjectToBool testing THIS
			// cast's LHS so a bare interface assignment (no null-check) still takes the pure path below.
			{
				const TSharedPtr<FKismetCompiledStatement> Paired = PeekStatement(1);
				const bool bClassLiteralOk = S->RHS.IsValidIndex(0) && S->RHS[0].IsValid()
					&& Cast<UClass>(S->RHS[0]->ObjectLiteral) != nullptr;
				if (bClassLiteralOk && S->LHS.IsValid() && S->RHS.IsValidIndex(1) && S->RHS[1].IsValid()
					&& Paired.IsValid() && Paired->Type == ECompiledStatementType::KCST_ObjectToBool
					&& Paired->RHS.IsValidIndex(0) && Paired->RHS[0].IsValid()
					&& Paired->RHS[0]->operator==(*S->LHS))
				{
					UEdGraphNode* CastNode = CreateCastNode(false);   // interface cast = UK2Node_DynamicCast (bIsMetaCast=false); pops cast + ObjectToBool (+ GotoIfNot/Goto)
					if (CastNode) { ++NodesCreated; CastNode->NodePosX = NextNodePosX; NextNodePosX += 320; }
					continue;   // CreateCastNode always advanced the cursor
				}
			}

			TSharedPtr<FKismetTerminal> DestClass = S->RHS.IsValidIndex(0) ? S->RHS[0] : nullptr;   // interface/object class literal
			TSharedPtr<FKismetTerminal> Source = S->RHS.IsValidIndex(1) ? S->RHS[1]                 // the value being cast
										   : (S->RHS.IsValidIndex(0) ? S->RHS[0] : nullptr);
			if (!S->LHS.IsValid() || !Source.IsValid())
			{
				EmitFailureComment(TEXT("interface-cast malformed (deferred)")); PopStatement(); continue;
			}
			UEdGraphPin* ResultPin = EmitInterfaceCastNode(DestClass, Source);
			if (!ResultPin)   // unresolved dest class → old non-crashing degrade
			{
				PassThroughTerminals.Add(FKismetTerminalAsKeyType(S->LHS), Source); PopStatement(); continue;
			}
			if (IsOutParamTerminal(S->LHS))
			{
				const FName OutName(*S->LHS->AssociatedVarProperty);
				// COLLAPSE (single-assign): the typed cast result goes straight to the FunctionResult input pin; pure
				// dataflow, no exec-map entry. As at the ObjectToBool site the VALUE is the emitted cast's OUTPUT PIN
				// (ResultPin), not S->RHS[0] (the class literal / source object). ResultPin is non-null here — the
				// unresolved-class case already degraded to a pass-through and continued out above.
				if (IsSingleAssignOutParam(OutName))
				{
					PopStatement();
					if (UEdGraphPin** RetPin = ReturnInputPinByName.Find(OutName)) MifLinkData(ResultPin, *RetPin);
					else EmitFailureComment(TEXT("interface-cast out-param collapse: Return pin missing"));
					continue;
				}
				const FName Local = MifLocalName(OutName);
				PopStatement();
				UK2Node_VariableSet* Set = MifSpawnLocalVarNode<UK2Node_VariableSet>(EditorGraph, OwnerBlueprint, Local, FVector2D(NextNodePosX, 0.0));
				if (Set)
				{
					++NodesCreated; Set->NodePosX = NextNodePosX; NextNodePosX += 320;
					if (UEdGraphPin* ExecIn = Set->FindPin(UEdGraphSchema_K2::PN_Execute, EGPD_Input)) NodeExecPinInputMap.Add(S, ExecIn);
					if (UEdGraphPin* ThenPin = Set->FindPin(UEdGraphSchema_K2::PN_Then, EGPD_Output))
					{
						const TSharedPtr<FKismetCompiledStatement> Succ = PeekNextValidStatement(0);
						if (Succ.IsValid()) ExecPinPatchUpMap.Add(ThenPin, Succ);
					}
					if (UEdGraphPin* ValPin = Set->FindPin(Local, EGPD_Input)) MifLinkData(ResultPin, ValPin);   // typed cast → local
				}
				else EmitFailureComment(TEXT("interface-cast out-param Set spawn failed"));
				continue;
			}
			IntermediateVariableHandles.Add(FKismetTerminalAsKeyType(S->LHS), ResultPin);
			PopStatement();
			continue;
		}

		if (!IsSupportedTopLevelStatement(S->Type))
		{
#if MIF_KR_DEBUG
			// Instrument the exact shape reaching the support gate. Types with dedicated handlers above (ObjectToBool=15,
			// CastObjToInterface=13, ...) should NEVER land here; if one does, this dumps enough to see WHY (paired-stmt
			// context, LHS/RHS shape) instead of guessing. See the degrade-rate investigation.
			UE_LOG(LogMifKismetReconstructor, Warning,
				TEXT("[decomp:UNSUPPORTED] type=%d | LHS=%s ctx=%d | RHSn=%d rhs0lit=%d | fn=%s | idx=%d/%d"),
				(int32) S->Type,
				S->LHS.IsValid() ? *S->LHS->AssociatedVarProperty : TEXT("<none>"),
				(S->LHS.IsValid() && S->LHS->Context.IsValid()) ? 1 : 0,
				S->RHS.Num(),
				(S->RHS.Num() && S->RHS[0].IsValid() && S->RHS[0]->bIsLiteral) ? 1 : 0,
				S->FunctionToCall ? *S->FunctionToCall->GetName() : TEXT("<none>"),
				CurrentStatementIndex, CompiledStatements.Num());
#endif
			EmitFailureComment(FString::Printf(TEXT("unsupported statement type %d"), (int32) S->Type));
			PopStatement();
			if (++FailureCount > 8) { bDegraded = true; break; }
			continue;
		}

		const int32 Before = CurrentStatementIndex;
		UEdGraphNode* Node = GenerateNodeForStatement();      // existing skeleton emitters (self-advancing)
		if (CurrentStatementIndex == Before)                  // no-progress guard (e.g. the CallFunction stub)
		{
			EmitFailureComment(TEXT("emitter made no progress"));
			PopStatement();
			if (++FailureCount > 8) { bDegraded = true; break; }
			continue;
		}
		if (Node) { ++NodesCreated; Node->NodePosX = NextNodePosX; NextNodePosX += 320; }
	}

	// ---------------- PASS 2: wire pins ----------------
	// ALWAYS wire, even on degrade. Previously a mid-reconstruction degrade skipped WireAllPins entirely, leaving every
	// node it had already created ORPHANED — "tons of nodes, zero exec flow": the graph LOOKS reconstructed but has no
	// execution spine, the worst possible read for a modder. WireAllPins is defensive (ResolveExecTarget threads past
	// missing/degraded statements; ResolveTerminalToPin leaves unresolved data pins at their default), so wiring a
	// PARTIAL reconstruction connects the portion that DID reconstruct and leaves honest gaps where it didn't — a
	// readable, mostly-working graph instead of a floating-node pile. The event is still flagged PARTIAL.
	WireAllPins();
	if (FailureCount > 0) bDegraded = true;
#if MIF_KR_DEBUG
	// FLOW-COMPLETENESS (honest metric): count exec-bearing nodes actually reachable from the entry's exec pin. The
	// "tons of nodes, zero flow" symptom = nodesCreated high but flowReached ~0. ok/degraded alone LIES about this — a
	// node-rich body with a dead exec spine is not usable however many nodes it has. (Event graphs are shared, so a
	// per-event total isn't cheap; nodesCreated is the proxy denominator.) Batch aggregates the [flow] lines.
	{
		TSet<UEdGraphNode*> Reached;
		TArray<UEdGraphNode*> Work;
		if (EntryThenPin)
			for (UEdGraphPin* L : EntryThenPin->LinkedTo)
				if (L && L->GetOwningNodeUnchecked()) Work.Add(L->GetOwningNode());
		while (Work.Num() > 0)
		{
			UEdGraphNode* N = Work.Pop(false);
			if (!N || Reached.Contains(N)) continue;
			Reached.Add(N);
			for (UEdGraphPin* P : N->Pins)
				if (P && P->Direction == EGPD_Output && P->PinType.PinCategory == UEdGraphSchema_K2::PC_Exec)
					for (UEdGraphPin* L : P->LinkedTo)
						if (L && L->GetOwningNodeUnchecked()) Work.Add(L->GetOwningNode());
		}
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[flow] %s: reached=%d nodesCreated=%d degraded=%d entryWired=%d"),
			Function ? *Function->GetName() : TEXT("?"), Reached.Num(), NodesCreated, bDegraded ? 1 : 0,
			(EntryThenPin && EntryThenPin->LinkedTo.Num() > 0) ? 1 : 0);
	}
#endif
	return true;
}

void FKismetGraphDecompiler::SetEventContext(UK2Node* InEventNode, const TMap<FName, FName>& InFrameParamMap,
	int32 InEntryStatementIndex, const TArray<int32>& InInitialFlowStack)
{
	bEventMode = true;
	EventEntryNode = InEventNode;
	FrameParamMap = InFrameParamMap;
	EntryStatementIndex = InEntryStatementIndex;
	InitialFlowStack = InInitialFlowStack;
}

void FKismetGraphDecompiler::EstablishTerminators()
{
	// ---- EVENT MODE: the event NODE is the terminator, in both directions ----
	// An event graph has no UK2Node_FunctionEntry and no UK2Node_FunctionResult, and it is SHARED by every event
	// on the Blueprint — so FindOrCreateEntryNode/FindOrCreateResultNode must not run at all here. Left to run,
	// they would scan the shared graph and could latch onto ANOTHER event's nodes.
	//
	// Downstream needs exactly two things from a terminator — EntryThenPin and ParamOutputPinByName — so inject
	// those from the event node and leave EntryNode/ResultNode null. ResultExecPin stays null on purpose: that is
	// what makes ResolveExecTarget END the exec chain at a KCST_Return, which is the correct reading of a return
	// inside an event slice (the event finishes; there is nothing to return to).
	if (bEventMode)
	{
		EntryNode = nullptr; ResultNode = nullptr; ResultExecPin = nullptr;
		EntryThenPin = nullptr; ParamOutputPinByName.Reset(); ReturnInputPinByName.Reset();

		if (!EventEntryNode)
		{
			EmitFailureComment(TEXT("event mode with no event node → nothing to hang the body off"));
			bDegraded = true;
			return;
		}

		// The event node's own pins are the authority for BOTH the exec entry and the parameter values.
		// ParamOutputPinByName is keyed on the name ResolveTerminalToPin looks up — the terminal's variable name,
		// i.e. the ubergraph FRAME property. So map FrameProp -> the pin named after the THUNK PARAM, using the
		// map the thunk's own bytecode states. A frame property with no entry is a genuine ubergraph temporary
		// and correctly falls through to the normal variable path.
		TMap<FName, UEdGraphPin*> PinByName;
		for (UEdGraphPin* P : EventEntryNode->Pins)
		{
			if (!P || P->Direction != EGPD_Output) continue;
			if (P->PinType.PinCategory == UEdGraphSchema_K2::PC_Exec) { EntryThenPin = P; continue; }
			// UK2Node_Event::DelegateOutputName ("OutputDelegate") — the event's own delegate handle, not a
			// parameter. Filtered by CATEGORY rather than by name so this holds for every event node class
			// (UK2Node_Event / _CustomEvent / _ComponentBoundEvent / input events) without a cast.
			if (P->PinType.PinCategory == UEdGraphSchema_K2::PC_Delegate) continue;
			PinByName.Add(P->PinName, P);
		}

		for (const TPair<FName, FName>& KV : FrameParamMap)
		{
			if (UEdGraphPin** Pin = PinByName.Find(KV.Value))
			{
				ParamOutputPinByName.Add(KV.Key, *Pin);
			}
			else
			{
				// The thunk names a parameter the spawned node has no pin for. Degrade this ONE pin (its reads
				// stay a frame-variable read) rather than mis-bind it to a different pin by position.
				EmitFailureComment(FString::Printf(
					TEXT("event param '%s' (frame '%s') has no output pin on %s → left as a variable read"),
					*KV.Value.ToString(), *KV.Key.ToString(), *EventEntryNode->GetClass()->GetName()));
			}
		}

		if (!EntryThenPin)
		{
			EmitFailureComment(TEXT("event node has no exec output → body cannot be wired"));
			bDegraded = true;
		}
		return;
	}

	EntryNode = FindOrCreateEntryNode();
	if (EntryNode) { EntryNode->NodePosX = 0; EntryNode->NodePosY = 0; }
	FindOrCreateResultNode();   // sets ResultNode (+ an initial pin scan we redo below after AddLocalVariable)

	// Reconstruct each MULTI-ASSIGN out-param as a function-scoped LOCAL variable. Its assignments (pass-1) become
	// Set(local) nodes in the exec flow and the single Return reads Get(local); the graph's own dataflow then
	// resolves branches / pre-branch writes / shared writes correctly (no result-node pin routing, no multi-return).
	//
	// An out-param assigned EXACTLY ONCE in the whole function needs none of that: with a single writer there is no
	// branch for two writes to collide on, so the value goes STRAIGHT to the FunctionResult input pin (see the pass-1
	// assignment sites) and recompiles to the cooked `Let(OutParam = value)` — instead of the local model's
	// `Let(local = value); Let(OutParam = local)`, whose extra statement is the dominant bytecode drift. Multi-assign
	// (and never-assigned) out-params keep the local verbatim: correctness beats fidelity, and they still drift.
	if (ResultNode && ReturnInputPinByName.Num() > 0)
	{
		// Snapshot (name, type) — AddLocalVariable marks the BP modified (→ synchronous skeleton recompile) and may
		// refresh node pins, so every KV.Value->PinType read happens HERE, before the first AddLocalVariable call.
		TArray<TPair<FName, FEdGraphPinType>> OutParams;
		for (const TPair<FName, UEdGraphPin*>& KV : ReturnInputPinByName)
			// A local is needed ONLY for a MULTI-assign out-param (≥2 writes, branch-safe). Single-assign COLLAPSES
			// (value → Return pin directly) and NEVER-assigned stays at its zero-default (no local, no Get) — both
			// recompile without the spurious `Let(OutParam = local)` the reconstructed local would otherwise add.
			if (!IsSingleAssignOutParam(KV.Key) && !IsNeverAssignedOutParam(KV.Key))
				OutParams.Add(TPair<FName, FEdGraphPinType>(KV.Key, KV.Value->PinType));
		for (const TPair<FName, FEdGraphPinType>& OP : OutParams)
			FBlueprintEditorUtils::AddLocalVariable(OwnerBlueprint, EditorGraph, MifLocalName(OP.Key), OP.Value, FString());
	}

	// Capture Entry pins AFTER AddLocalVariable (pin pointers captured earlier could have been invalidated by a refresh).
	EntryThenPin = nullptr; ParamOutputPinByName.Reset();
	if (EntryNode)
		for (UEdGraphPin* P : EntryNode->Pins)
		{
			if (!P || P->Direction != EGPD_Output) continue;
			if (P->PinType.PinCategory == UEdGraphSchema_K2::PC_Exec) EntryThenPin = P;
			else ParamOutputPinByName.Add(P->PinName, P);
		}

	// Capture Result pins fresh (AFTER the AddLocalVariable calls above, which may have refreshed them) + wire
	// Get(local) → each MULTI-ASSIGN out-param input pin. A collapsed (single-assign) out-param gets NO getter — its
	// pin is still registered in ReturnInputPinByName so the pass-1 assignment sites can find and bind it directly.
	ReturnInputPinByName.Reset(); ResultExecPin = nullptr;
	if (ResultNode)
		for (UEdGraphPin* P : ResultNode->Pins)
		{
			if (!P || P->Direction != EGPD_Input) continue;
			if (P->PinType.PinCategory == UEdGraphSchema_K2::PC_Exec) { ResultExecPin = P; continue; }
			ReturnInputPinByName.Add(P->PinName, P);
			const bool bCollapsed = IsSingleAssignOutParam(P->PinName);
			const bool bNeverAssigned = IsNeverAssignedOutParam(P->PinName);
#if MIF_KR_DEBUG
			UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[outparam:%s] '%s' assigns=%d -> %s"),
				Function ? *Function->GetName() : TEXT("?"), *P->PinName.ToString(),
				OutParamAssignCount.FindRef(P->PinName),
				bNeverAssigned ? TEXT("DEFAULT (never assigned: no local, pin left at zero-default)")
					 : bCollapsed ? TEXT("DIRECT (collapsed: no local, value → Return pin)")
						   : TEXT("LOCAL (kept: branch-safe, +1 stmt drift)"));
#endif
			// Never-assigned: leave the pin at its signature default (no Get) — cooked emits nothing for it.
			// Single-assign (collapsed): the pass-1 site binds the value straight to this pin (no Get).
			if (bCollapsed || bNeverAssigned) continue;
			const FName Local = MifLocalName(P->PinName);
			UK2Node_VariableGet* Get = MifSpawnLocalVarNode<UK2Node_VariableGet>(
				EditorGraph, OwnerBlueprint, Local, FVector2D(NextNodePosX, 520.0));
			if (Get)
			{
				++NodesCreated; NextNodePosX += 220;
				if (UEdGraphPin* Out = Get->FindPin(Local, EGPD_Output)) MifLinkData(Out, P);
			}
		}

	// EMPTY-STUB SHAPE — byte-identical fix for the "trailing default-Let" drift bucket (largest of the corpus, 164
	// drifting BPs; workflow wf_504d4b49 CONFIRMED). An interface stub / empty function compiles COOKED to a bare
	// `Return(Nothing)`: its UK2Node_FunctionResult was never exec-wired, so PruneIsolatedNodes removed it
	// (KismetCompiler GatherRootSet roots only Entry/Event/Timeline; Result is not root-set). Our reconstruction
	// otherwise wires Entry.Then→Result.exec, making the Result node REACHABLE → the backend then emits one
	// `Let(OutParam = type-zero)` per unconnected out-param pin (FKCHandler_VariableSet::GenerateAssigments has NO
	// zero-default skip gate) → N spurious statements vs cooked's zero. Clearing the pin default is inert
	// (ValidateAndRegisterNetIfLiteral registers a literal even for an empty default). Reproduce the PRUNING instead:
	// null ResultExecPin so nothing wires Entry.Then to the Result node → it is left isolated → pruned on recompile →
	// cooked-identical bare Return. Native out-params are zero-initialised on frame setup, so dropping the zero-Let is
	// behavior-preserving.
	//
	// The body-shape guard (whole body is only Return/Nop) is LOAD-BEARING, not merely conservative: a function like
	// `Let(A = value); Return` that ALSO has a second never-assigned out-param B must KEEP its Result node reachable —
	// A's value feeds a Result DATA pin, and pruning the node would silently DROP A's return value. Restricting to the
	// pure-stub shape (nothing is returned) makes removing the Result node provably behavior-preserving. Never fires on
	// void functions (ResultNode == nullptr) or on the branch+local testbed (its out-params are assigned).
	if (!bEventMode && ResultNode && ResultExecPin)
	{
		bool bHasNeverAssignedOutParam = false;
		for (const TPair<FName, UEdGraphPin*>& KV : ReturnInputPinByName)
			if (IsNeverAssignedOutParam(KV.Key)) { bHasNeverAssignedOutParam = true; break; }
		bool bBodyIsBareReturn = true;
		for (const TSharedPtr<FKismetCompiledStatement>& S : CompiledStatements)
		{
			if (!S.IsValid()) continue;
			if (S->Type == ECompiledStatementType::KCST_Return || S->Type == ECompiledStatementType::KCST_Nop) continue;
			bBodyIsBareReturn = false;
			break;
		}
		if (bHasNeverAssignedOutParam && bBodyIsBareReturn)
		{
#if MIF_KR_DEBUG
			UE_LOG(LogMifKismetReconstructor, Warning,
				TEXT("[outparam:%s] EMPTY STUB → Result node left isolated (matches cooked pruned-Result bare Return)"),
				Function ? *Function->GetName() : TEXT("?"));
#endif
			ResultExecPin = nullptr;
		}
	}
}

UK2Node_FunctionEntry* FKismetGraphDecompiler::FindOrCreateEntryNode()
{
	TArray<UK2Node_FunctionEntry*> Found;
	EditorGraph->GetNodesOfClass<UK2Node_FunctionEntry>(Found);
	return Found.Num() ? Found[0] : nullptr;   // AddFunctionGraph already placed it
}

UK2Node_FunctionResult* FKismetGraphDecompiler::FindOrCreateResultNode()
{
	if (ResultNode) return ResultNode;
	TArray<UK2Node_FunctionResult*> Found;
	EditorGraph->GetNodesOfClass<UK2Node_FunctionResult>(Found);
	if (!Found.Num()) return nullptr;          // void function: no result node exists, none needed
	ResultNode = Found[0];
	for (UEdGraphPin* P : ResultNode->Pins)
	{
		if (P->Direction != EGPD_Input) continue;
		if (P->PinType.PinCategory == UEdGraphSchema_K2::PC_Exec) ResultExecPin = P;
		else ReturnInputPinByName.Add(P->PinName, P);
	}
	return ResultNode;
}

void FKismetGraphDecompiler::HandleReturnStatement(TSharedPtr<FKismetCompiledStatement> S)
{
	// EVENT MODE: a KCST_Return inside an event slice is the END OF THE EVENT, not a function return. It is the
	// ubergraph's single shared Return — every event's flow-stack pop lands on it — and it must NOT be given a
	// UK2Node_FunctionResult: events have no return values, and an event graph has no Result node to find.
	// Emitting no exec mapping for S is exactly right: ResolveExecTarget then returns the (null) ResultExecPin,
	// which terminates the exec chain — the correct reconstruction of "the event ends here".
	if (bEventMode) { return; }

	FindOrCreateResultNode();
	if (ResultExecPin) NodeExecPinInputMap.Add(S, ResultExecPin);
	// Assignment-return model: values already delivered by prior out-param Let assignments, so S->RHS is empty.
	// If a build ever carries return values on the Return statement itself, wire them here by name.
	for (const TSharedPtr<FKismetTerminal>& T : S->RHS)
	{
		if (!T.IsValid()) continue;
		if (UEdGraphPin** Pin = ReturnInputPinByName.Find(FName(*T->AssociatedVarProperty)))
		{
			RecordTerminalRead(*Pin, T);
		}
	}
}

bool FKismetGraphDecompiler::TryHandleOutParamAssignment(TSharedPtr<FKismetCompiledStatement> S)
{
	if (!S->LHS.IsValid() || S->LHS->Context.IsValid()) return false;
	UEdGraphPin** ResultPin = ReturnInputPinByName.Find(FName(*S->LHS->AssociatedVarProperty));
	if (!ResultPin) return false;
	// Register the assigned value against the FunctionResult input pin (literal → default, variable → wire).
	if (S->RHS.Num() > 0 && S->RHS[0].IsValid())
	{
		RecordTerminalRead(*ResultPin, S->RHS[0]);
	}
	return true;   // handled without a node; exec falls through this statement
}

bool FKismetGraphDecompiler::IsSupportedTopLevelStatement(ECompiledStatementType T) const
{
	switch (T)
	{
	case ECompiledStatementType::KCST_Assignment:
	case ECompiledStatementType::KCST_CallFunction:
	case ECompiledStatementType::KCST_DynamicCast:
	case ECompiledStatementType::KCST_MetaCast:
	case ECompiledStatementType::KCST_CreateArray:
	case ECompiledStatementType::KCST_CreateMap:
	case ECompiledStatementType::KCST_CreateSet:
		return true;
	default:
		return false;
	}
}

bool FKismetGraphDecompiler::IsOutParamTerminal(const TSharedPtr<FKismetTerminal>& T) const
{
	return T.IsValid() && !T->Context.IsValid() && ReturnInputPinByName.Contains(FName(*T->AssociatedVarProperty));
}

// Emits a VISIBLE degrade-reason comment into the reconstructed graph — in EVERY build. Previously this was
// #if MIF_KR_DEBUG-gated AND log-only (it returned nullptr and, despite its name, spawned no comment), so in a
// shipping build every per-pin/per-statement degrade reason silently vanished. It now spawns a real
// UEdGraphNode_Comment the user actually sees, which is what the name has always promised.
//
// Emitting the comment is a PURE SIDE EFFECT: the function STILL returns nullptr, so the long-standing "degrade"
// contract every caller relies on (the `return EmitFailureComment(...)` sites, the driver's no-progress guard, and
// the fidelity control metric) is byte-for-byte unchanged. A comment node is editor-cosmetic and compiles to no
// bytecode, so it cannot perturb the recompiled-function comparison the verifier scores. Degrades softly: if the
// graph or node allocation is unavailable, it simply skips the comment.
UEdGraphNode* FKismetGraphDecompiler::EmitFailureComment(const FString& Reason)
{
#if MIF_KR_DEBUG
	UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[reconstruct:%s] %s"),
		Function ? *Function->GetName() : TEXT("?"), *Reason);
#endif
	if (EditorGraph)
	{
		if (UEdGraphNode_Comment* CommentNode = NewObject<UEdGraphNode_Comment>(EditorGraph, NAME_None, RF_Transactional))
		{
			CommentNode->NodeComment = FString::Printf(TEXT("[MifKR degrade] %s"), *Reason);
			CommentNode->NodePosX = NextNodePosX;
			CommentNode->NodePosY = FailureCommentPosY;
			CommentNode->NodeWidth = 460;
			CommentNode->NodeHeight = 88;
			CommentNode->CommentColor = FLinearColor(0.45f, 0.12f, 0.12f);
			EditorGraph->AddNode(CommentNode, /*bUserAction*/ false, /*bSelectNewNode*/ false);
			CommentNode->CreateNewGuid();
			FailureCommentPosY += 112;   // stack successive degrade comments so they don't overlap
		}
	}
	return nullptr;
}

void FKismetGraphDecompiler::CollapseToStub()
{
	bDegraded = true;
	if (EntryThenPin && ResultExecPin) EntryThenPin->MakeLinkTo(ResultExecPin);
}

// ============================ PASS 2 ============================

void FKismetGraphDecompiler::WireAllPins()
{
	// Phase B: data pins (plain links; wildcard type propagation deferred to Phase D)
	for (const TPair<UEdGraphPin*, TSharedPtr<FKismetTerminal>>& KV : TerminalPatchUpMap)
	{
		ResolveTerminalToPin(KV.Value, KV.Key);
	}

	// Phase B.5: type each reconstructed Get Data Table Row node's OutRow (Result) pin. UK2Node_GetDataTableRow derives
	// the row struct type from its DataTable asset's RowStruct in RefreshOutputPinType (via PostReconstructNode); the
	// DataTable default/link was set in Phase B. Before WireExecFlow so exec links aren't disturbed.
	for (UEdGraphNode* Node : EditorGraph->Nodes)
	{
		UK2Node_GetDataTableRow* DT = Cast<UK2Node_GetDataTableRow>(Node);
		if (!DT) continue;
		if (UScriptStruct** RowStruct = DataTableRowStructByNode.Find(DT))   // member-variable table → our CDO-resolved struct
		{
			if (*RowStruct)
				if (UEdGraphPin* R = DT->GetResultPin())   // mirrors SetReturnTypeForStruct without the private method
				{
					R->PinType.PinCategory = UEdGraphSchema_K2::PC_Struct;
					R->PinType.PinSubCategoryObject = *RowStruct;
				}
		}
		else DT->PostReconstructNode();   // literal-default table → engine self-types OutRow
	}

	// Phase C: exec flow
	WireExecFlow();

	// Phase C.5: type multi-element MakeContainer nodes. NotifyPinConnectionListChanged only adopts the element type
	// on the output-first (0 linked) or single-element (1 linked) transient; our batch link-then-propagate never
	// exposes that for a 2+-element node, so a MakeArray feeding FText::Format(InArgs) stays wildcard. PostReconstructNode
	// adopts the type from the OUTPUT link unconditionally and propagates it to every element pin.
	for (UEdGraphNode* Node : EditorGraph->Nodes)
	{
		UK2Node_MakeContainer* Container = Cast<UK2Node_MakeContainer>(Node);
		if (!Container) continue;
		UEdGraphPin* Out = Container->GetOutputPin();
		if (Out && Out->PinType.PinCategory == UEdGraphSchema_K2::PC_Wildcard
			&& Out->LinkedTo.Num() > 0 && Out->LinkedTo[0]
			&& Out->LinkedTo[0]->PinType.PinCategory != UEdGraphSchema_K2::PC_Wildcard)
		{
			Container->PostReconstructNode();   // types Array + [0]/[1]; the fixpoint below cascades downstream
		}
	}

	// Phase D: now that ALL links exist, propagate wildcard/container types. Doing it here (not per-link) means
	// PinConnectionListChanged can't invalidate a pin pointer we were still wiring with. SKIP FunctionEntry/
	// FunctionResult: their pins are signature-typed (no wildcards) and PinConnectionListChanged can reconstruct
	// the node, DROPPING the exec link we just made in Phase C.
	//
	// Iterate to a FIXPOINT: a wildcard CHAIN (Make Array → Add → Get → Length) resolves one hop per pass — the
	// type has to cascade from the one typed end through every wildcard node — so a single pass leaves the far end
	// undetermined. Re-snapshot each pass (PinConnectionListChanged may reconstruct nodes → stale pin pointers) and
	// stop when the wildcard-pin count stops shrinking.
	auto CountWildcardPins = [&]() -> int32
	{
		int32 Count = 0;
		for (UEdGraphNode* Node : EditorGraph->Nodes)
			if (Node)
				for (UEdGraphPin* P : Node->Pins)
					if (P && P->PinType.PinCategory == UEdGraphSchema_K2::PC_Wildcard) ++Count;
		return Count;
	};
	for (int32 Pass = 0; Pass < 8; ++Pass)
	{
		const int32 WildcardsBefore = CountWildcardPins();
		TArray<UEdGraphNode*> NodesSnapshot = EditorGraph->Nodes;
		for (UEdGraphNode* Node : NodesSnapshot)
		{
			if (!Node) continue;
			if (Cast<UK2Node_FunctionResult>(Node) || Cast<UK2Node_FunctionEntry>(Node)
				|| Cast<UK2Node_GetDataTableRow>(Node)) continue;   // OutRow authoritatively typed in B.5; PinConnectionListChanged would re-wildcard it
			TArray<UEdGraphPin*> PinsSnapshot = Node->Pins;
			for (UEdGraphPin* P : PinsSnapshot)
			{
				// Only propagate DATA pins — notifying an exec pin can make the node re-wire its exec (doubling a link).
				if (P && P->LinkedTo.Num() > 0 && P->PinType.PinCategory != UEdGraphSchema_K2::PC_Exec)
					Node->PinConnectionListChanged(P);
			}
		}
		if (CountWildcardPins() >= WildcardsBefore) break;   // no more wildcards resolved → converged
	}

	// Phase E: reintroduce elided super→sub object downcasts (all pin types are concrete now).
	InsertObjectDowncastConversions();

	// Prune fully-orphaned empty MakeArray/MakeSet/MakeMap temps (no pin connections at all) — leftovers from container
	// literals whose consumer was reconstructed differently; they serve no purpose and only clutter the graph. Matched
	// on the MakeContainer BASE (not MakeArray alone): a stranded zero-input MakeSet/MakeMap would otherwise survive as
	// an all-wildcard node and raise a NEW "The type of @@ is undetermined" error.
	{
		TArray<UEdGraphNode*> Orphans;
		for (UEdGraphNode* Node : EditorGraph->Nodes)
		{
			if (!Cast<UK2Node_MakeContainer>(Node)) continue;
			bool bAnyLink = false;
			for (UEdGraphPin* P : Node->Pins) if (P && P->LinkedTo.Num() > 0) { bAnyLink = true; break; }
			if (!bAnyLink) Orphans.Add(Node);
		}
		for (UEdGraphNode* N : Orphans) { --NodesCreated; EditorGraph->RemoveNode(N); }
	}

#if MIF_KR_DEBUG
	// Report any node still holding a wildcard pin after propagation, with what its wildcard pins link to — this
	// pinpoints where a container type failed to flow in (empty MakeArray, unwired array source, etc.).
	for (UEdGraphNode* Node : EditorGraph->Nodes)
	{
		if (!Node) continue;
		for (UEdGraphPin* P : Node->Pins)
		{
			if (!P || P->PinType.PinCategory != UEdGraphSchema_K2::PC_Wildcard) continue;
			if (UK2Node_FormatText* FT = Cast<UK2Node_FormatText>(Node))
				if (P->Direction == EGPD_Input && P != FT->GetFormatPin()) continue;   // FormatText arg pins are wildcard-until-typed — not a concern
			FString LinkStr;
			for (UEdGraphPin* L : P->LinkedTo)
				if (L && L->GetOwningNodeUnchecked())
					LinkStr += FString::Printf(TEXT("%s.%s "), *L->GetOwningNodeUnchecked()->GetName(), *L->PinName.ToString());
			UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[wildcard] %s.%s links=%d -> %s"),
				*Node->GetName(), *P->PinName.ToString(), P->LinkedTo.Num(), LinkStr.IsEmpty() ? TEXT("<none>") : *LinkStr);
		}
	}
#endif
}

// Phase E: any DATA link whose SOURCE object pin is a strict SUPERCLASS of its DEST object pin (Actor → BP_ItemDropBag)
// is schema-incompatible (no implicit downcast) and fails compile — the SpawnActor/FinishSpawningActor idiom whose cast
// the cooked compiler elided (it retyped the FinishSpawningActor ReturnValue pin to the subclass). Splice a pure
// UK2Node_DynamicCast to the dest class between them (collect-then-mutate so LinkedTo isn't mutated mid-iteration).
void FKismetGraphDecompiler::InsertObjectDowncastConversions()
{
	struct FPendingDowncast { UEdGraphPin* Src; UEdGraphPin* Dst; UClass* DstClass; };
	TArray<FPendingDowncast> Pending;
	UClass* CallingCtx = OwnerBlueprint ? OwnerBlueprint->SkeletonGeneratedClass : nullptr;

	TArray<UEdGraphNode*> NodesSnapshot = EditorGraph->Nodes;
	for (UEdGraphNode* Node : NodesSnapshot)
	{
		if (!Node || Cast<UK2Node_DynamicCast>(Node)) continue;   // never re-cast a cast result (idempotent)
		TArray<UEdGraphPin*> PinsSnapshot = Node->Pins;
		for (UEdGraphPin* Out : PinsSnapshot)
		{
			if (!Out || Out->Direction != EGPD_Output) continue;
			if (Out->PinType.PinCategory != UEdGraphSchema_K2::PC_Object || Out->PinType.IsContainer()) continue;
			UClass* SrcClass = Cast<UClass>(Out->PinType.PinSubCategoryObject.Get());
			if (!SrcClass || SrcClass->IsChildOf(UInterface::StaticClass())) continue;

			TArray<UEdGraphPin*> LinkedSnapshot = Out->LinkedTo;
			for (UEdGraphPin* Dst : LinkedSnapshot)
			{
				if (!Dst || Dst->Direction != EGPD_Input) continue;
				if (Dst->PinType.PinCategory != UEdGraphSchema_K2::PC_Object || Dst->PinType.IsContainer()) continue;
				if (K2Schema->ArePinTypesCompatible(Out->PinType, Dst->PinType, CallingCtx)) continue;   // legal upcast/equal — leave it
				UClass* DstClass = Cast<UClass>(Dst->PinType.PinSubCategoryObject.Get());
				if (!DstClass || DstClass->IsChildOf(UInterface::StaticClass())) continue;
				if (!DstClass->GetAuthoritativeClass()->IsChildOf(SrcClass->GetAuthoritativeClass())) continue;   // only genuine downcasts
				Pending.Add({ Out, Dst, DstClass });
			}
		}
	}

	for (const FPendingDowncast& P : Pending)
	{
		UClass* DstClass = P.DstClass;
		UK2Node_DynamicCast* CastNode = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_DynamicCast>(
			EditorGraph, FVector2D(NextNodePosX, 420.0), EK2NewNodeFlags::None,
			[DstClass](UK2Node_DynamicCast* N){ N->TargetType = DstClass; N->SetPurity(true); });   // pure => no exec pins
		if (!CastNode) { EmitFailureComment(TEXT("downcast relink: cast spawn failed (deferred)")); continue; }
		++NodesCreated; CastNode->NodePosX = NextNodePosX; NextNodePosX += 220;

		UEdGraphPin* CastSrc = CastNode->GetCastSourcePin();   // PN_ObjectToCast (wildcard until connected)
		UEdGraphPin* CastRes = CastNode->GetCastResultPin();   // PC_Object, TargetType == DstClass
		if (!CastSrc || !CastRes) { EmitFailureComment(TEXT("downcast relink: cast pins missing (deferred)")); continue; }

		P.Src->BreakLinkTo(P.Dst);                             // drop the incompatible super→sub direct link
		P.Src->MakeLinkTo(CastSrc);                            // superclass source → cast input
		CastRes->MakeLinkTo(P.Dst);                            // subclass cast result → original dest (exact type)
		CastNode->NotifyPinConnectionListChanged(CastSrc);     // wildcard → PC_Object (Phase D already ran; retype ourselves)
	}
}

TSharedPtr<FKismetTerminal> FKismetGraphDecompiler::ResolvePassThrough(TSharedPtr<FKismetTerminal> T) const
{
	int32 Guard = 0;
	while (T.IsValid() && Guard++ < 32)
	{
		const TSharedPtr<FKismetTerminal>* Next = PassThroughTerminals.Find(FKismetTerminalAsKeyType(T));
		if (!Next) break;
		T = *Next;
	}
	return T;
}

bool FKismetGraphDecompiler::IsSelfTerminal(const TSharedPtr<FKismetTerminal>& T) const
{
	return T.IsValid() && T->Type.PinSubCategory == UEdGraphSchema_K2::PSC_Self;
}

// Mirrors UK2Node_VariableSet::ShouldFlushDormancyOnSet(): the variable's source class is AActor-derived AND the
// property is CPF_Net. Asking the node itself is impossible here — this runs on the statement BEFORE the Set, so the
// node does not exist yet (the original author's TODO called exactly this out: "during standard code generation we
// cannot really know what statement we had coming before us … detect it in CreateFunctionCallNode() and just discard").
//
// The engine's whole Transform is gated on !HasFieldNotificationBroadcast(), which is NOT re-tested here: when that is
// true the compiler emits NO FlushNetDormancy at all, so there is no such statement in the cooked stream to match and
// the caller's lookahead can never fire. Resolving the context mirrors CreateVariableSetNode's own ContextTypeStruct.
bool FKismetGraphDecompiler::WillRepSetReemitFlushNetDormancy(const TSharedPtr<FKismetCompiledStatement>& SetStmt)
{
	if (!SetStmt.IsValid() || SetStmt->Type != ECompiledStatementType::KCST_Assignment) return false;
	const TSharedPtr<FKismetTerminal> LHS = SetStmt->LHS;
	if (!LHS.IsValid() || LHS->AssociatedVarProperty.IsEmpty()) return false;
	if (IsLocalVariable(LHS)) return false;      // a local can never be a replicated property
	if (IsOutParamTerminal(LHS)) return false;   // handled by the out-param block → no UK2Node_VariableSet → nothing re-emits a Flush

	UStruct* ContextTypeStruct =
		(LHS->VarType == FKismetTerminal::EVarType_Instanced && !LHS->Context.IsValid() && OwnerBlueprint)
			? (UStruct*) OwnerBlueprint->SkeletonGeneratedClass
			: ResolveContextTerminalType(LHS->Context);

	const UClass* VariableSourceClass = Cast<UClass>(ContextTypeStruct);
	if (!VariableSourceClass || !VariableSourceClass->IsChildOf(AActor::StaticClass())) return false;

	const FProperty* Property = VariableSourceClass->FindPropertyByName(FName(*LHS->AssociatedVarProperty));
	return Property && (Property->PropertyFlags & CPF_Net);
}

// ONE shared UK2Node_Self per graph, spawned on first use. Its output is PN_Self / PC_Object+PSC_Self
// (UK2Node_Self::AllocateDefaultPins), which the schema resolves to the owning blueprint's own class — so it upcasts
// cleanly into any UObject*/AActor* parameter pin. The node is re-queried for its pin on every call rather than the pin
// being cached: Phase D's PinConnectionListChanged can reconstruct a node and invalidate raw pin pointers.
UEdGraphPin* FKismetGraphDecompiler::GetOrCreateSelfNodeOutput()
{
	if (!SelfNodeCache)
	{
		SelfNodeCache = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_Self>(
			EditorGraph, FVector2D(NextNodePosX, 560.0), EK2NewNodeFlags::None);
		if (!SelfNodeCache) return nullptr;   // caller soft-degrades (pin left at its default)
		++NodesCreated; NextNodePosX += 220;
#if MIF_KR_DEBUG
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[self-node] spawned shared UK2Node_Self for graph '%s'"),
			EditorGraph ? *EditorGraph->GetName() : TEXT("?"));
#endif
	}
	return SelfNodeCache->FindPin(UEdGraphSchema_K2::PN_Self, EGPD_Output);
}

void FKismetGraphDecompiler::RecordTerminalRead(UEdGraphPin* ReaderPin, TSharedPtr<FKismetTerminal> Terminal)
{
	if (!ReaderPin) return;
	TerminalPatchUpMap.Add(ReaderPin, Terminal);
	// Snapshot the producer of this intermediate AS OF NOW. Pass-1 runs in statement order, so the current
	// IntermediateVariableHandles entry is the latest write BEFORE this read — correct even when the compiler
	// reuses one temp slot across several producers (e.g. two Map_Find calls both writing CallFunc_Map_Find_Value:
	// the branch reads the bool at stmt1 → find#1; OutVal reads the value at stmt3 → find#2).
	if (Terminal.IsValid())
		if (UEdGraphPin** P = IntermediateVariableHandles.Find(FKismetTerminalAsKeyType(Terminal)))
			IntermediateSnapshotByReader.Add(ReaderPin, *P);
}

void FKismetGraphDecompiler::ResolveTerminalToPin(TSharedPtr<FKismetTerminal> T, UEdGraphPin* Pin)
{
	if (!T.IsValid() || !Pin) return;
	T = ResolvePassThrough(T);
	if (!T.IsValid()) return;

	if (T->InlineGeneratedParameter.IsValid())            // pure sub-expr (Select/GetArrayItem/MathExpr) — deferred
	{
		EmitFailureComment(TEXT("inline pure sub-expression (deferred)"));
		return;
	}
	// (d) EX_Self. MUST be tested BEFORE bIsLiteral: the transformer builds the Self terminal through
	// ProcessLiteralExpression, so it carries bIsLiteral=true (PC_Object + PSC_Self, with NO ObjectLiteral and an empty
	// StringLiteral). The literal branch below would therefore swallow every self terminal, and ApplyLiteralToPin would
	// fall past its `ObjectLiteral` test into TrySetDefaultValue(Pin, "") — a silent NO-OP that leaves the pin bare.
	// (That is the ACTUAL mechanism of the (Self)→(NoObject) drift; the old `if (IsSelfTerminal(T)) return;` that used to
	// sit AFTER the literal test was unreachable dead code, which is why "leave the pin default" looked correct.)
	//
	// WHICH pin the self targets decides the reconstruction — the two cases are NOT interchangeable:
	//
	//   * the hidden self/TARGET pin (always named PN_Self — FBlueprintNodeStatics::CreateSelfPin names it that in all
	//     three of its branches, as do UK2Node_CreateDelegate/VariableGet/VariableSet) is created with PinSubCategory
	//     PSC_Self, so KismetCompilerVMBackend emits EX_Self for it even when left unconnected. Leaving the pin bare
	//     recompiles to the identical (Self) term → unchanged behaviour, and identical to today's no-op.
	//
	//   * a REAL PARAMETER pin (e.g. the WorldContextObject of GetDDSGameMode/GetCharacterMeta/GetShopMeta/IsValidGuid)
	//     is a plain typed object pin. The backend's literal path is explicit:
	//         if (Term->Type.PinSubCategory == PN_Self)  Writer << EX_Self;
	//         else if (!Term->ObjectLiteral)             Writer << EX_NoObject;
	//     so a bare object param compiles to (NoObject), NOT (Self) — a genuine semantic change (a null world context
	//     can fail at runtime). It must be reconstructed as an EXPLICIT UK2Node_Self, whose output pin IS PSC_Self and
	//     therefore re-emits EX_Self. (PN_Self and PSC_Self are both the FName "self", so that test matches.)
	//
	// Gated on the PIN NAME, never on "wildcard only": these params are concretely typed object pins, so a wildcard
	// gate would never fire. MifLinkData (plain MakeLinkTo) is mandatory here — Phase B is iterating TerminalPatchUpMap,
	// so nothing in this path may reconstruct a node or touch that map (hence no RecordTerminalRead either).
	if (IsSelfTerminal(T))
	{
		if (Pin->PinName == UEdGraphSchema_K2::PN_Self) return;        // self/target pin → leave default (as today)
		if (UEdGraphPin* SelfOut = GetOrCreateSelfNodeOutput())
		{
			// INTERNAL-USE-ONLY pins must be left alone. UK2Node_AddComponent's hidden "Component Template Context"
			// takes EX_Self in the cooked bytecode, but the compiler fills that pin ITSELF and hard-errors on a manual
			// link ("This parameter is for internal use only"). Reconstructing the Construction Script exposed this —
			// AddComponent lives there — and regressed 22 previously-passing BPs.
			// The marker is bNotConnectable ON THE PIN: UK2Node_CallFunction::CreatePinsForFunctionCall does
			//     Pin->bNotConnectable = InternalPins.Contains(Pin->PinName);   (K2Node_CallFunction.cpp:1245)
			// fed by FBlueprintEditorUtils::GetHiddenPinsForFunction's OutInternalPins ("subset of hidden pins marked
			// for internal use only"). NOTE: UEdGraphSchema_K2::CanCreateConnection does NOT consult this flag, so
			// asking the schema is useless here — test the flag directly. The pin's existing default is already what
			// the compiler wants.
			if (Pin->bNotConnectable)
			{
#if MIF_KR_DEBUG
				UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[self-param] '%s' on '%s' is internal-use-only (bNotConnectable) — left at default"),
					*Pin->PinName.ToString(),
					Pin->GetOwningNodeUnchecked() ? *Pin->GetOwningNodeUnchecked()->GetName() : TEXT("?"));
#endif
				return;
			}
#if MIF_KR_DEBUG
			UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[self-param] Self -> real param pin '%s' on '%s' (was NoObject)"),
				*Pin->PinName.ToString(),
				Pin->GetOwningNodeUnchecked() ? *Pin->GetOwningNodeUnchecked()->GetName() : TEXT("?"));
#endif
			MifLinkData(SelfOut, Pin);
		}
		else EmitFailureComment(FString::Printf(
			TEXT("Self node unavailable for param pin '%s' → left at default (compiles as NoObject; deferred)"),
			*Pin->PinName.ToString()));
		return;
	}

	if (T->bIsLiteral) { ApplyLiteralToPin(T, Pin); return; }          // (a) literal → pin default

	// (params-into-body / setter value source) — dodges the terminal hash
	if (UEdGraphPin** Pp = ParamOutputPinByName.Find(FName(*T->AssociatedVarProperty)))
	{
		MifLinkData(*Pp, Pin);
		return;
	}
	// (b) intermediate temp → producing node's output pin. Prefer the read-time snapshot: when the compiler reuses
	// a temp slot for several producers, this binds THIS read to the producer that was live when it was read,
	// not the last producer globally (which is what the plain IntermediateVariableHandles lookup would give).
	if (UEdGraphPin** Snap = IntermediateSnapshotByReader.Find(Pin))
	{
		MifLinkData(*Snap, Pin);
		return;
	}
	if (UEdGraphPin** Ip = IntermediateVariableHandles.Find(FKismetTerminalAsKeyType(T)))
	{
		MifLinkData(*Ip, Pin);
		return;
	}
	// (b') STRUCT-CONTEXT ALIAS of an intermediate temp — the inverse of the alias CreateMakeStructNode already
	// registers, and the single root cause behind BOTH event-body census families (§8 "No DataTable in @@" x29 via
	// the GetDataTableRow OutRow, §9 "No input structure to break" x35).
	//
	// The chain, measured, not assumed (DDS2 batch log, e.g. BP_InventoryComponent::ItemTypeFailure):
	//   1. GetItemMeta(ItemId, OutItemData) registers its write-only out-param under the ARG terminal's key. The arg
	//      is a plain EX_LocalVariable read → ContextType_Object.
	//   2. The body then reads OutItemData.Member. EX_StructMemberContext MUTATES ITS OWN COPY of that same local
	//      terminal to ContextType_Struct (KismetBytecodeTransformer.cpp:508) and hangs the member off it.
	//   3. GetOrCreateStructMemberBreak hands that STRUCT-form terminal back here to wire the BreakStruct's input.
	//      FKismetTerminal::operator== and GetTypeHash both fold ContextType in (KismetIntermediateFormat.h:185,207),
	//      so the Object-form registration from step 1 MISSES — even though it is the same temp, produced in-slice.
	//   4. The read falls to GetOrCreateVariableGetter → IsLocalVariable → AddLocalVariable, which REFUSES a
	//      GT_Ubergraph graph → the pin is left dangling → UK2Node_BreakStruct::EarlyValidation errors out and the
	//      whole Blueprint's compile FAILS (taking its already-correct functions down with it).
	// The FUNCTION path hides this: AddLocalVariable succeeds there, so step 4 mints a getter on a never-assigned
	// local. That COMPILES (hence PASS) while reading a default — one of the 1348 drifting functions, not a clean one.
	//
	// Resolving the alias wires the BreakStruct to the REAL producer pin, which is the correct graph in BOTH modes.
	// It is nonetheless gated to bEventMode: the events-OFF control (PASS 1235/21, fidelity 56.78%) is the baseline
	// this task must not perturb, and ungating this changes function output. Ungate it only behind its own measured
	// batch — the expectation is a fidelity GAIN (drift → ident), but that is a claim to measure, not to assume.
	if (bEventMode && T->ContextType == FKismetTerminal::EContextType_Struct && !T->Context.IsValid())
	{
		TSharedPtr<FKismetTerminal> ValueKey = MakeShareable(new FKismetTerminal(*T));
		ValueKey->ContextType = FKismetTerminal::EContextType_Object;   // the plain-local read form it was registered as
		if (UEdGraphPin** Ap = IntermediateVariableHandles.Find(FKismetTerminalAsKeyType(ValueKey)))
		{
#if MIF_KR_DEBUG
			UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[struct-alias] '%s' struct-form read → producer pin %s.%s"),
				*T->AssociatedVarProperty,
				(*Ap)->GetOwningNodeUnchecked() ? *(*Ap)->GetOwningNodeUnchecked()->GetName() : TEXT("?"),
				*(*Ap)->PinName.ToString());
#endif
			MifLinkData(*Ap, Pin);
			return;
		}
	}
	// struct-member read: the transformer's StructMemberContext sets ContextType_Struct on the struct VALUE
	// (T->Context), NOT on the member terminal. Reconstruct as a UK2Node_BreakStruct on that value; the member pin
	// is named after T->AssociatedVarProperty. (Object-member reads carry Context->ContextType == Object and fall
	// through to the variable getter below.)
	if (T->Context.IsValid() && T->Context->ContextType == FKismetTerminal::EContextType_Struct)
	{
		if (UK2Node_BreakStruct* Break = GetOrCreateStructMemberBreak(T->Context))
		{
			if (UEdGraphPin* Out = Break->FindPin(FName(*T->AssociatedVarProperty), EGPD_Output)) MifLinkData(Out, Pin);
			else EmitFailureComment(FString::Printf(TEXT("struct-member pin not found: member='%s' struct='%s'"),
				*T->AssociatedVarProperty, Break->StructType ? *Break->StructType->GetName() : TEXT("?")));
		}
		return;
	}
	// (c) real variable read → lazy cached getter
	if (UK2Node_VariableGet* G = GetOrCreateVariableGetter(T))
	{
		if (UEdGraphPin* Out = G->FindPin(FName(*T->AssociatedVarProperty), EGPD_Output)) MifLinkData(Out, Pin);
		else EmitFailureComment(FString::Printf(TEXT("getter output pin not found: var='%s' vt=%d ctxValid=%d"),
			*T->AssociatedVarProperty, (int32) T->VarType, T->Context.IsValid() ? 1 : 0));
	}
	else EmitFailureComment(FString::Printf(TEXT("getter unresolved (no VarSource): var='%s' vt=%d ctxValid=%d"),
		*T->AssociatedVarProperty, (int32) T->VarType, T->Context.IsValid() ? 1 : 0));
}

UK2Node_VariableGet* FKismetGraphDecompiler::GetOrCreateVariableGetter(TSharedPtr<FKismetTerminal> T)
{
	FKismetTerminalAsKeyType Key(T);
	if (UK2Node_VariableGet** Hit = VariableGetterCache.Find(Key)) return *Hit;

	// Compiler-generated LOCAL variable (ForEach-loop counters/index, temp arrays like EndStats): reconstruct it
	// as a REAL function-local variable and reference it via SetLocalMember. ConfigureVarNode would make a
	// member-style reference against the function scope -> a broken "None" getter whose output pin doesn't exist.
	// (Intermediates are resolved earlier in ResolveTerminalToPin, so anything reaching here is a genuine local.)
	if (IsLocalVariable(T) && !T->AssociatedVarProperty.IsEmpty())
	{
		const FName LocalName(*T->AssociatedVarProperty);
		if (!FBlueprintEditorUtils::FindLocalVariable(OwnerBlueprint, EditorGraph, LocalName)
			&& !FBlueprintEditorUtils::AddLocalVariable(OwnerBlueprint, EditorGraph, LocalName, T->Type, FString()))
		{
			// AddLocalVariable REFUSES any graph that is not GT_Function (BlueprintEditorUtils.cpp:5292) — it
			// returns false without adding. That is exactly the event path: the target is the Blueprint's EVENT
			// graph (GT_Ubergraph), which has no UK2Node_FunctionEntry to hang LocalVariables on, because event
			// graphs genuinely cannot have local variables. The ubergraph's "locals" are its persistent-frame
			// temporaries; an event param is rewired to the event node's pin before we ever get here, and a temp
			// produced inside this slice resolves as an intermediate — so reaching this point means a read whose
			// producer is NOT in the slice.
			//
			// Ignoring the false (as this did) would leave FindLocalVariableGuidByName returning an invalid GUID
			// and mint a getter pointing at a local that does not exist: a "None" getter that fails compile. Say
			// so and degrade instead — the caller then labels the event body as PARTIAL rather than shipping a
			// graph that looks whole.
			EmitFailureComment(FString::Printf(
				TEXT("local '%s' cannot be created in a '%s' graph (AddLocalVariable requires GT_Function) → read unresolved"),
				*LocalName.ToString(), *EditorGraph->GetName()));
			bDegraded = true;
			return nullptr;
		}
		const FGuid Guid = FBlueprintEditorUtils::FindLocalVariableGuidByName(OwnerBlueprint, EditorGraph, LocalName);
		UK2Node_VariableGet* LocalGet = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_VariableGet>(
			EditorGraph, FVector2D(NextNodePosX, 300.0), EK2NewNodeFlags::None,
			[&](UK2Node_VariableGet* N) { N->VariableReference.SetLocalMember(LocalName, EditorGraph->GetName(), Guid); });
		NextNodePosX += 220; ++NodesCreated;
		VariableGetterCache.Add(Key, LocalGet);
		return LocalGet;
	}

	// Self-member instance variables carry no explicit context (implicit self) → resolve to the owner
	// class, not the function (ResolveContextTerminalType returns the Function for a null context).
	UStruct* VarSource;
	if (T->VarType == FKismetTerminal::EVarType_Instanced && (!T->Context.IsValid() || IsSelfTerminal(T->Context)))
	{
		VarSource = OwnerBlueprint ? OwnerBlueprint->SkeletonGeneratedClass : nullptr;
	}
	else
	{
		VarSource = ResolveContextTerminalType(T->Context);
	}
	if (!VarSource) return nullptr;
	const FName VarName(*T->AssociatedVarProperty);
#if MIF_KR_DEBUG
	UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[getter] var='%s' vt=%d source='%s' onSource=%d"),
		*VarName.ToString(), (int32) T->VarType, *VarSource->GetName(), VarSource->FindPropertyByName(VarName) ? 1 : 0);
#endif

	UK2Node_VariableGet* G = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_VariableGet>(
		EditorGraph, FVector2D(NextNodePosX, 300.0), EK2NewNodeFlags::None,
		[&](UK2Node_VariableGet* Node) { UEdGraphSchema_K2::ConfigureVarNode(Node, VarName, VarSource, OwnerBlueprint); });
	NextNodePosX += 220; ++NodesCreated;

	VariableGetterCache.Add(Key, G);   // add before recursion so self-referential chains terminate

	if (T->Context.IsValid() && !IsSelfTerminal(T->Context))
	{
		if (UEdGraphPin* SelfIn = G->FindPin(UEdGraphSchema_K2::PN_Self, EGPD_Input))
		{
			ResolveTerminalToPin(T->Context, SelfIn);
			// If the context could NOT be wired (producer not in slice, unresolvable alias, an object-temp whose value
			// doesn't reach here, …), a member getter with an unconnected REQUIRED Target pin is a hard COMPILE FAIL
			// ("self is not a <Class>; therefore Target must have a connection"). Degrade instead: destroy the getter,
			// drop it from the cache, mark the body PARTIAL. The CONSUMER data pin is then left at its default (which
			// COMPILES) rather than the whole Blueprint failing. This is the doctrine — degrade, never break — and it is
			// what lets object-typed temps be aliased safely (an unwireable one degrades here instead of failing).
			if (SelfIn->LinkedTo.Num() == 0)
			{
				VariableGetterCache.Remove(Key);
				G->DestroyNode();
				if (NodesCreated > 0) { --NodesCreated; }
				EmitFailureComment(FString::Printf(
					TEXT("getter '%s': non-self context could not be wired → Target would be unconnected (deferred)"),
					*VarName.ToString()));
				bDegraded = true;
				return nullptr;
			}
		}
	}
	return G;
}

// Struct-member READ: one shared UK2Node_BreakStruct per struct VALUE (StructContextTerminal), exposing every member
// as an output pin. The caller (ResolveTerminalToPin) picks the member-named pin. The struct value's producer is
// resolved through the same uniform ResolveTerminalToPin path (object/self getter, intermediate temp, struct literal,
// param, or a NESTED struct-member read A.B.C which recurses back here and bottoms out at the first object source).
UK2Node_BreakStruct* FKismetGraphDecompiler::GetOrCreateStructMemberBreak(TSharedPtr<FKismetTerminal> StructContextTerminal)
{
	if (!StructContextTerminal.IsValid()) return nullptr;
	FKismetTerminalAsKeyType Key(StructContextTerminal);
	if (UK2Node_BreakStruct** Hit = StructMemberBreakCache.Find(Key)) return *Hit;

	// The struct value types as PC_Struct with the UScriptStruct in PinSubCategoryObject (CreateMakeStructNode
	// convention). Degrade rather than crash on an unresolved (cooked-only/other-pak) struct.
	UScriptStruct* ScriptStruct = Cast<UScriptStruct>(StructContextTerminal->Type.PinSubCategoryObject);
	if (!ScriptStruct)
	{
		EmitFailureComment(TEXT("struct-member read: unresolved struct type (deferred)"));
		return nullptr;
	}

	// StructType is read by AllocateDefaultPins (runs after this lambda) to build the struct input pin + one output
	// pin per BlueprintVisible member; PostPlacedNewNode sets bMadeAfterOverridePinRemoval so no legacy compile note.
	UK2Node_BreakStruct* Break = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_BreakStruct>(
		EditorGraph, FVector2D(NextNodePosX, 300.0), EK2NewNodeFlags::None,
		[ScriptStruct](UK2Node_BreakStruct* N){ N->StructType = ScriptStruct; });
	if (!Break)
	{
		EmitFailureComment(TEXT("struct-member read: BreakStruct spawn failed (deferred)"));
		return nullptr;
	}
	NextNodePosX += 220; ++NodesCreated;

	// Cache BEFORE wiring the input so repeated / self-referential struct values share this node and terminate.
	StructMemberBreakCache.Add(Key, Break);

	// Struct INPUT pin (named after the struct); fall back to the lone input struct pin the engine handler also scans for.
	UEdGraphPin* StructIn = Break->FindPin(ScriptStruct->GetFName(), EGPD_Input);
	if (!StructIn)
		for (UEdGraphPin* P : Break->Pins)
			if (P && P->Direction == EGPD_Input && P->PinType.PinCategory == UEdGraphSchema_K2::PC_Struct) { StructIn = P; break; }

	if (StructIn) ResolveTerminalToPin(StructContextTerminal, StructIn);
	else EmitFailureComment(TEXT("struct-member read: break node has no struct input pin (deferred)"));

	return Break;
}

// True for the only container-literal shape the cooked compiler emits: an EMPTY ArrayConst/SetConst/MapConst. The
// transformer builds "(elem,elem,…)" and writes "()" for zero elements; a terminal that never had its StringLiteral
// set is "" — treat both as empty.
static bool MifIsEmptyContainerLiteral(const FString& InLiteral)
{
	const FString Trimmed = InLiteral.TrimStartAndEnd();
	return Trimmed.IsEmpty() || Trimmed == TEXT("()");
}

UEdGraphPin* FKismetGraphDecompiler::EmitContainerLiteralNode(const TSharedPtr<FKismetTerminal>& T, UEdGraphPin* Pin)
{
	if (!T.IsValid() || !Pin) return nullptr;

	// Elements are NOT recoverable: the transformer flattens an ArrayConst/SetConst/MapConst into a single
	// StringLiteral and drops the per-element terminals. Emitting a 0-input container for a NON-empty literal would
	// silently discard data — worse than the (unchanged) compile error, so degrade LOUDLY instead. Believed
	// unreachable: a container literal can only originate from a pin the schema ACCEPTED a default on, and neither a
	// FunctionResult input nor an auto-create-ref-term pin has editor UI to author elements, so it is always "()".
	if (!MifIsEmptyContainerLiteral(T->StringLiteral))
	{
		EmitFailureComment(FString::Printf(
			TEXT("non-empty container literal '%s' on pin '%s' (elements not preserved by the transformer; deferred)"),
			*T->StringLiteral, *Pin->PinName.ToString()));
		return nullptr;
	}

#if MIF_KR_DEBUG
	// Log the TAKEN branch: this is the one line that proves (or refutes) the root cause in a single run — that the
	// terminal reaching here really IS a container literal, rather than the pin having never received a terminal at
	// all (an alternative hypothesis with an IDENTICAL symptom: unlinked pin, empty default, no diagnostic).
	UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[container-literal] '%s' (container=%d) -> MakeContainer on pin '%s'"),
		*T->StringLiteral, (int32) T->Type.ContainerType, *Pin->PinName.ToString());
#endif

	// Spawn the matching MakeContainer with ZERO inputs. NumInputs must be set in the SpawnNode lambda: it runs BEFORE
	// AllocateDefaultPins, which allocates the output pin plus NumInputs input pins. FKCHandler_MakeContainer::Compile
	// then emits KCST_CreateArray with an empty RHS => EX_SetArray(temp, []), and there is no minimum-element check.
	const FVector2D NodePos(NextNodePosX, 640.0);
	UK2Node_MakeContainer* Container = nullptr;

	switch (T->Type.ContainerType)
	{
	case EPinContainerType::Array:
		Container = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_MakeArray>(
			EditorGraph, NodePos, EK2NewNodeFlags::None,
			[](UK2Node_MakeArray* N) { N->NumInputs = 0; });
		break;
	case EPinContainerType::Set:
		Container = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_MakeSet>(
			EditorGraph, NodePos, EK2NewNodeFlags::None,
			[](UK2Node_MakeSet* N) { N->NumInputs = 0; });
		break;
	case EPinContainerType::Map:
		Container = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_MakeMap>(
			EditorGraph, NodePos, EK2NewNodeFlags::None,
			[](UK2Node_MakeMap* N) { N->NumInputs = 0; });
		break;
	default:
		return nullptr;   // not a container terminal — caller must not have routed here
	}

	if (!Container)
	{
		EmitFailureComment(TEXT("container-literal MakeContainer spawn failed (deferred)"));
		return nullptr;
	}
	++NodesCreated; NextNodePosX += 220;

	UEdGraphPin* Out = Container->GetOutputPin();
	if (!Out)
	{
		EmitFailureComment(TEXT("container-literal node has no output pin (deferred)"));
		return nullptr;
	}

	// MifLinkData (plain MakeLinkTo, no PinConnectionListChanged): Phase B must not reconstruct a node while we are
	// still wiring, and must not touch TerminalPatchUpMap (we are iterating it). The wildcard output is typed later by
	// the existing Phase C.5 PostReconstructNode pass, which adopts the type from this very OUTPUT link.
	MifLinkData(Out, Pin);
	return Out;
}

void FKismetGraphDecompiler::ApplyLiteralToPin(const TSharedPtr<FKismetTerminal>& T, UEdGraphPin* Pin)
{
	// A container (array/set/map) literal cannot always be a pin default. UEdGraphSchema_K2::TrySetDefaultValue gates
	// the assignment on IsPinDefaultValid and returns void — so when the schema rejects the default it does NOTHING,
	// SILENTLY, leaving the pin unlinked with DefaultValue "". At compile, FKCHandler_VariableSet ->
	// ValidateAndRegisterNetIfLiteral then reports "Default value '' for <pin> is invalid: 'Array inputs (like
	// '<pin>') must have an input wired into them'". That is exactly how an out-param array literal fails: the
	// out-param-as-local model relocates it OFF a UK2Node_FunctionResult input pin (which IsPinDefaultValid EXEMPTS)
	// ONTO a UK2Node_VariableSet value pin (which it does not).
	//
	// Ask the schema the SAME question TrySetDefaultValue asks. If it ACCEPTS (its three exemptions: FunctionResult
	// input / auto-create-ref-term / Interface BP), fall through to the unchanged path — behaviour byte-identical to
	// before. If it REJECTS, the default is impossible and the path below is a proven no-op, so reconstruct the
	// literal as a MakeArray/MakeSet/MakeMap node instead. The container rejection is value-INDEPENDENT (it reads only
	// Pin->PinType and the owning node), so passing the raw StringLiteral rather than the normalised value cannot
	// change the verdict.
	if (T->Type.ContainerType != EPinContainerType::None && Pin->PinType.IsContainer()
		&& !K2Schema->IsPinDefaultValid(Pin, T->StringLiteral, nullptr, FText::GetEmpty()).IsEmpty())
	{
		EmitContainerLiteralNode(T, Pin);   // soft-degrades to nullptr; pin then left exactly as it is today
		return;
	}

	const FName Cat = Pin->PinType.PinCategory;
	if ((Cat == UEdGraphSchema_K2::PC_Object || Cat == UEdGraphSchema_K2::PC_Class || Cat == UEdGraphSchema_K2::PC_Interface) && T->ObjectLiteral)
	{
		K2Schema->TrySetDefaultObject(*Pin, T->ObjectLiteral);
	}
	else if (Cat == UEdGraphSchema_K2::PC_Text)
	{
		Pin->DefaultTextValue = T->TextLiteral;
	}
	else
	{
		// numeric / bool / name / byte / string / struct-literal-text / soft-ref path.
		//
		// ENUM-TYPED BYTE LITERAL — the value is LOST unless the number is converted to the enumerant NAME first.
		// The transformer records every EX_ByteConst as PC_Byte + a NUMERIC StringLiteral ("3") and cannot do better:
		// the bytecode carries no enum type (see its own "Enums in Kismet are represented as byte constants" TODO). The
		// enum lives only on the PIN. UEdGraphSchema_K2::DefaultValueSimpleValidation's PC_Byte branch validates a pin
		// whose PinSubCategoryObject is a UEnum with `EnumPtr->GetIndexByNameString(NewDefaultValue) == INDEX_NONE` —
		// "3" is not an enumerant NAME, so it is rejected; TrySetDefaultValue gates the WHOLE assignment on
		// IsPinDefaultValid and returns void, so it SILENTLY does nothing. The pin keeps its autogenerated default,
		// which for an enum is deliberately left EMPTY (= entry index 0). Result: SetCollisionEnabled(QueryAndPhysics=3)
		// reconstructs as NoCollision(0) — it COMPILES CLEAN and silently breaks collision. Only the verifier caught it.
		//
		// Fix: convert value → enumerant name via the engine's own convention for enum pin defaults
		// (`Pin->DefaultValue = Enum->GetNameStringByValue(v)`, as UK2Node_SpawnActorFromClass does). GetNameStringByValue
		// strips the "EEnum::" scope, and GetIndexByNameString (the validator) strips-or-adds it, so the short form is
		// accepted. Applies to PC_Enum as well as PC_Byte — both carry the UEnum in PinSubCategoryObject.
		const bool bEnumPin = (Cat == UEdGraphSchema_K2::PC_Byte || Cat == UEdGraphSchema_K2::PC_Enum);
		UEnum* PinEnum = bEnumPin ? Cast<UEnum>(Pin->PinType.PinSubCategoryObject.Get()) : nullptr;
		int32 LiteralValue = 0;
		if (PinEnum && !T->StringLiteral.IsEmpty() && FDefaultValueHelper::ParseInt(T->StringLiteral, LiteralValue))
		{
			// Out of range (sparse/renamed enumerant) → GetNameStringByValue returns EMPTY (GetIndexByValue gives
			// INDEX_NONE, GetNameStringByIndex is IsValidIndex-guarded, so this NEVER asserts). Degrade to the existing
			// path rather than stamping "" (which would read as the 0th entry — the very bug being fixed).
			const FString EnumEntryName = PinEnum->GetNameStringByValue(static_cast<int64>(LiteralValue));
			if (!EnumEntryName.IsEmpty())
			{
#if MIF_KR_DEBUG
				UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[enum-literal] pin '%s' enum '%s': %d -> '%s'"),
					*Pin->PinName.ToString(), *PinEnum->GetName(), LiteralValue, *EnumEntryName);
#endif
				K2Schema->TrySetDefaultValue(*Pin, EnumEntryName);
				return;
			}
			EmitFailureComment(FString::Printf(
				TEXT("byte literal %d is not a valid value of enum '%s' on pin '%s' → left at default (deferred)"),
				LiteralValue, *PinEnum->GetName(), *Pin->PinName.ToString()));
		}
		K2Schema->TrySetDefaultValue(*Pin, T->StringLiteral);
	}
}

void FKismetGraphDecompiler::WireExecFlow()
{
	// AddFunctionGraph seeds the stub with a default Entry→Result exec link (for functions with a Result
	// node); remove it so our reconstructed exec flow is the only wiring (else the entry exec-out gets 2 links).
	if (EntryThenPin) EntryThenPin->BreakAllPinLinks();

	if (EntryThenPin)
	{
		// EntryStatementIndex, not 0: on the event path the slice's first statement need not be the event's own
		// entry (a slice that jumps backwards into an earlier-laid-out region has statements below it), and
		// hanging the event node off the wrong statement would wire a plausible-looking, silently wrong body.
		if (UEdGraphPin* In = ResolveExecTarget(EntryStatementIndex)) EntryThenPin->MakeLinkTo(In);
	}
	for (const TPair<UEdGraphPin*, TSharedPtr<FKismetCompiledStatement>>& KV : ExecPinPatchUpMap)
	{
		if (!KV.Key || KV.Key->LinkedTo.Num() > 0) continue;   // an exec-out takes exactly one connection
		const int32* Idx = StatementIndexMap.Find(KV.Value);
		if (!Idx) continue;
		if (UEdGraphPin* In = ResolveExecTarget(*Idx)) KV.Key->MakeLinkTo(In);
	}
}

UEdGraphPin* FKismetGraphDecompiler::ResolveExecTarget(int32 Start)
{
	TSet<int32> Visited;
	return ResolveExecTarget(Start, Visited);
}

UEdGraphPin* FKismetGraphDecompiler::ResolveExecTarget(int32 i, TSet<int32>& Visited)
{
	while (CompiledStatements.IsValidIndex(i))
	{
		TSharedPtr<FKismetCompiledStatement> S = CompiledStatements[i];
		if (!S.IsValid()) { ++i; continue; }
		switch (S->Type)
		{
		case ECompiledStatementType::KCST_Nop:
			++i; continue;
		case ECompiledStatementType::KCST_Return:
		case ECompiledStatementType::KCST_GotoReturn:
			// Multi-return: this statement was flushed into a SPECIFIC FunctionResult node — thread to that
			// node's exec-in, not the shared/first one. Fall back to ResultExecPin only if never mapped.
			if (UEdGraphPin** In = NodeExecPinInputMap.Find(S)) return *In;
			return ResultExecPin;
		case ECompiledStatementType::KCST_UnconditionalGoto:
		{
			if (Visited.Contains(i)) return nullptr;
			Visited.Add(i);
			if (!S->TargetLabel.IsValid()) return nullptr;
			const int32* Tgt = StatementIndexMap.Find(S->TargetLabel);
			if (!Tgt) return nullptr;
			i = *Tgt; continue;
		}
		case ECompiledStatementType::KCST_EndOfThread:
		{
			// Pop the flow-stack → thread to the resolved pop target (loop-back / structured return). Falls back to
			// the function Return if the stack was empty (a bare thread-end = implicit return).
			if (Visited.Contains(i)) return nullptr;
			Visited.Add(i);
			if (TSharedPtr<FKismetCompiledStatement>* Tgt = FlowStackPopTarget.Find(S))
				if (Tgt->IsValid())
					if (const int32* Idx = StatementIndexMap.Find(*Tgt)) { i = *Idx; continue; }
			return ResultExecPin;
		}
		default:
			if (UEdGraphPin** In = NodeExecPinInputMap.Find(S)) return *In;
			++i; continue;
		}
	}
	return ResultExecPin;   // ran off the end → implicit return (may be null for void)
}
