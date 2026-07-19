#include "MifKismetReconstructorModule.h"
#include "MifReconstructorDebug.h"
#include "MifReconstructPipeline.h"
#include "CompiledBlueprintReconstructor.h"
#include "Modules/ModuleManager.h"

DEFINE_LOG_CATEGORY(LogMifKismetReconstructor);

// Private/Verify/MifFidelityVerifier.cpp — the Level-1 bytecode fidelity self-check.
extern void MifKr_BindFidelityVerifier();
extern void MifKr_UnbindFidelityVerifier();

void FMifKismetReconstructorModule::StartupModule()
{
	// Phase 4: bind the engine's "Make Uncooked Blueprint Copy" (F3) hook so each reconstructed function graph is
	// filled with real decompiled nodes instead of an empty stub. Bound here (module load, after Kismet) so it is
	// live long before any user invokes the action.
	GetBlueprintFunctionGraphReconstructor().BindLambda([](UFunction* SourceFunc, UEdGraph* TargetGraph, UBlueprint* OwnerBP)
	{
		const bool bOk = MifReconstructFunctionIntoGraph(SourceFunc, TargetGraph, OwnerBP);
		UE_LOG(LogMifKismetReconstructor, Log, TEXT("[F3] reconstruct %s → %s"),
			SourceFunc ? *SourceFunc->GetName() : TEXT("?"), bOk ? TEXT("ok") : TEXT("degraded"));
		return bOk;   // surfaced to the batch harness as the reconstructed-function tally
	});

	// Phase 2 (ubergraph → per-event split): fill EVENT bodies. A SECOND delegate rather than a wider signature on
	// the one above — that one is bound and working for 1228 BPs, and changing its arity would force a lockstep
	// engine+plugin update and break any other consumer. Unbound → event nodes stay bare stubs (no regression);
	// bound but `mif.kr.Events 0` (the default) → the same, decided plugin-side so the engine stays clean.
	GetBlueprintEventGraphReconstructor().BindLambda([](UFunction* EventThunk, UEdGraph* EventGraph,
		UK2Node* EventNode, UBlueprint* OwnerBP)
	{
		const bool bOk = MifReconstructEventIntoGraph(EventThunk, EventGraph, EventNode, OwnerBP);
		UE_LOG(LogMifKismetReconstructor, Log, TEXT("[F3] reconstruct event %s → %s"),
			EventThunk ? *EventThunk->GetName() : TEXT("?"), bOk ? TEXT("ok") : TEXT("degraded"));
		return bOk;   // surfaced to the batch harness as the reconstructed-EVENT tally (a separate denominator)
	});

	// Level-1 fidelity self-check: after the engine compiles a reconstructed copy, diff each function's RECOMPILED
	// bytecode against the cooked original. Unbound → the engine skips verification entirely, so binding here is what
	// makes mif.kr.VerifyFidelity (and ReconstructAll's opt-in 'verify' columns) work at all.
	MifKr_BindFidelityVerifier();

	UE_LOG(LogMifKismetReconstructor, Log,
		TEXT("MifKismetReconstructor loaded (Phase 4: F3 'Make Uncooked Blueprint Copy' hook bound; fidelity verifier bound). ")
		TEXT("Console: mif.kr.Reconstruct <BP> <Func> | mif.kr.VerifyFidelity <BP> [child]"));
}

void FMifKismetReconstructorModule::ShutdownModule()
{
	GetBlueprintFunctionGraphReconstructor().Unbind();
	GetBlueprintEventGraphReconstructor().Unbind();
	MifKr_ResetUbergraphCache();   // never let a cached raw cooked UFunction*/UClass* outlive the module
	MifKr_UnbindFidelityVerifier();
	UE_LOG(LogMifKismetReconstructor, Log, TEXT("MifKismetReconstructor unloaded."));
}

IMPLEMENT_MODULE(FMifKismetReconstructorModule, MifKismetReconstructor)
