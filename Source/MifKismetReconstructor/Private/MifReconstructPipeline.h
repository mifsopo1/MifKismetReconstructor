#pragma once

#include "CoreMinimal.h"

class UFunction;
class UEdGraph;
class UBlueprint;
class UK2Node;

// Disassemble SourceFunc's cooked bytecode → transform to the compiled-statement IR → decompile into TargetGraph
// (which the caller has already created via AddFunctionGraph<UFunction> with SourceFunc's signature).
// Does NOT compile the owning Blueprint — the caller decides when to compile. Returns false if the decompiler
// degraded (partial reconstruction). This is the single shared entry point used by BOTH the mif.kr.Reconstruct
// console command AND the "Make Uncooked Blueprint Copy" (F3) engine hook.
bool MifReconstructFunctionIntoGraph(UFunction* SourceFunc, UEdGraph* TargetGraph, UBlueprint* OwnerBP);

// Fill an EVENT's body (ubergraph → per-event split). The host has ALREADY spawned the entry node (UK2Node_Event /
// UK2Node_CustomEvent / ...) into the Blueprint's event graph; this slices the cooked ubergraph at the event's
// entry and wires the body off that node's exec output.
//
// EventThunk is the cooked stub UFunction for the event. It carries BOTH the entry offset (as the EX_IntConst
// first argument of its call into the ubergraph) AND the param→frame map (its EX_LetValueOnPersistentFrame
// statements) — which is exactly why no offset appears in this signature: every bytecode concern stays here, on
// the plugin side. The ubergraph itself is likewise derived (EventThunk's owner class → UberGraphFunction) rather
// than passed, so the engine fork never has to reason about ubergraph identity.
//
// DEGRADE UNIT = ONE EVENT: returns false and leaves the node as a stub with a failure comment; the caller carries
// on with the next event. Gated by the `mif.kr.Events` CVar (default off → returns false, i.e. today's behaviour).
bool MifReconstructEventIntoGraph(UFunction* EventThunk, UEdGraph* EventGraph, UK2Node* EventNode, UBlueprint* OwnerBP);

// Drop the cached ubergraph decode (single-slot, per-Blueprint). The cache self-invalidates on a key change, so
// this is only needed at module shutdown, to make sure no raw cooked pointer outlives the module.
void MifKr_ResetUbergraphCache();
