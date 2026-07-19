#pragma once
#include "CoreMinimal.h"
#include "AssetGeneration/KismetIntermediateFormat.h"
#include "EdGraphSchema_K2.h"

class UK2Node_CreateDelegate;
class UK2Node_BaseMCDelegate;
class UK2Node_BreakStruct;
class UK2Node_GetDataTableRow;
class UDataTable;
class UScriptStruct;

struct FKismetTerminalAsKeyType {
public:
    TSharedPtr<FKismetTerminal> Terminal;
    FORCEINLINE FKismetTerminalAsKeyType(const TSharedPtr<FKismetTerminal>& Terminal) : Terminal(Terminal) {}

    FORCEINLINE bool operator==(const FKismetTerminalAsKeyType& Other) const {
        return Terminal->operator==(*Other.Terminal);
    }
};

FORCEINLINE uint32 GetTypeHash(const FKismetTerminalAsKeyType& Key) {
    return GetTypeHash(*Key.Terminal);
}

/** A planned FText::Format collapse: InPattern + result terminal + ordered (argName, value) list, extracted from the
    MakeStruct(FFormatArgumentData)/MakeArray/Format IR chain so it can be rebuilt as one UK2Node_FormatText (that
    struct is BlueprintInternalUseOnly, so a hand-authored MakeStruct on it can't compile). */
struct FFormatTextCollapsePlan {
    TSharedPtr<FKismetTerminal> PatternTerminal;   // InPattern (the Format call's RHS[0])
    TSharedPtr<FKismetTerminal> ResultTerminal;    // the Format call's LHS
    TArray<TPair<FString, TSharedPtr<FKismetTerminal>>> Args;   // (argName, value) in array order
    bool bPatternIsLiteral = false;
};

class FKismetGraphDecompiler {
public:
    /** Constructs decompiler object for provided function and graph */
    FKismetGraphDecompiler(UFunction* Function, UEdGraph* Graph);

    /** Initializes decompiler with the compiled kismet statement list */
    void Initialize(const TArray<TSharedPtr<FKismetCompiledStatement>>& Statements);

    /** PHASE 3 DRIVER: pass-1 (spawn nodes) + pass-2 (wire pins) into TargetGraph. Returns false if degraded. */
    bool Run(UFunction* SourceFunc, const TArray<TSharedPtr<FKismetCompiledStatement>>& Statements, UEdGraph* TargetGraph, UBlueprint* OwnerBP);

    /** EVENT MODE (ubergraph → per-event split). Call BEFORE Run(); Run() deliberately does not reset it.
        Statements must then be ONE EVENT'S SLICE — the statements reachable from the event's entry, kept in
        ASCENDING OFFSET ORDER so that array adjacency still means bytecode fall-through (it does: if a reached
        statement falls through, its fall-through target is the immediately-next statement and is reached too, so
        no un-reached statement can ever come between two slice neighbours that fall through to each other).

        InEntryStatementIndex = the event's entry, as an index into that slice. It is NOT assumed to be 0: a slice
        that jumps backwards into a region laid out earlier (exactly what a SHARED region looks like) has
        statements below its own entry. Rooting the walks at a hardcoded 0 would silently start the reconstruction
        at the wrong statement — on a whole ubergraph it would start at the prologue and fall through the computed
        jump into a different event entirely.

        InEventNode = the entry node the HOST already spawned (UK2Node_Event / UK2Node_CustomEvent / ...). An event
        graph has NO UK2Node_FunctionEntry and NO UK2Node_FunctionResult, so the event node supplies the exec-out
        and the param output pins instead, and a KCST_Return simply ENDS the exec chain (no Result node exists to
        thread into — a return in an event slice is the end of the event, not a function return).

        InFrameParamMap = (ubergraph FRAME property → the event node's OUTPUT PIN name), read authoritatively out
        of the thunk's own EX_LetValueOnPersistentFrame statements. Event params are NOT ubergraph parameters: the
        thunk copies them into frame properties and the body reads THOSE, so every read must be rewired to the
        event node's pin. The generated frame name is uniquified and must never be reconstructed by rule.

        InInitialFlowStack = [B] the flow stack AS IT ACTUALLY IS at the entry offset — i.e. [ReturnAddress] when
        the ubergraph has the prologue push, NOT empty. Empty ONLY when the BP genuinely has no flow stack. Given
        as indices into the SLICE (Statements). Seeding empty would drop the return address and mis-resolve every
        EndOfThread. */
    void SetEventContext(class UK2Node* InEventNode, const TMap<FName, FName>& InFrameParamMap,
                         int32 InEntryStatementIndex, const TArray<int32>& InInitialFlowStack);
    int32 GetNodesCreated() const { return NodesCreated; }
    int32 GetStatementsProcessed() const { return StatementsProcessed; }
    bool WasDegraded() const { return bDegraded; }
private:
    // ---- PHASE 3 driver / terminators / pass-2 (KismetGraphDecompiler_Reconstruct.cpp) ----
    bool RunGuardedBody();
    void EstablishTerminators();
    /** Pre-scan (runs BEFORE EstablishTerminators): count out-param assignments PER NAME across ALL statements, so
        EstablishTerminators and the pass-1 assignment sites can agree on which out-params collapse. */
    void ScanOutParamAssignCounts();
    /** Pre-pass: simulate the exec CFG maintaining the Kismet flow-stack (KCST_PushState pushes a continuation,
        KCST_EndOfThread(IfNot) pops+gotos it) and record each pop's target statement into FlowStackPopTarget,
        so pass-2 wires loop-back / structured-return exec instead of dead-ending. */
    void ResolveFlowStackTargets();
    class UK2Node_FunctionEntry* FindOrCreateEntryNode();
    class UK2Node_FunctionResult* FindOrCreateResultNode();
    void HandleReturnStatement(TSharedPtr<FKismetCompiledStatement> Stmt);
    bool TryHandleOutParamAssignment(TSharedPtr<FKismetCompiledStatement> Stmt);
    bool IsSupportedTopLevelStatement(ECompiledStatementType StmtType) const;
    /** True if the terminal is a context-less out-param write target (delivers into a FunctionResult input by name). */
    bool IsOutParamTerminal(const TSharedPtr<FKismetTerminal>& Terminal) const;
    UEdGraphNode* EmitFailureComment(const FString& Reason);
    void CollapseToStub();
    void WireAllPins();
    /** Phase E (after the wildcard fixpoint): splice a pure UK2Node_DynamicCast into any super→sub PC_Object data
        link (e.g. Actor→BP_ItemDropBag off FinishSpawningActor) the cooked compiler elided — the schema has no
        implicit downcast, so such a raw link fails compile. */
    void InsertObjectDowncastConversions();
    void ResolveTerminalToPin(TSharedPtr<FKismetTerminal> Terminal, UEdGraphPin* TargetPin);
    /** Record a terminal read (TerminalPatchUpMap) AND snapshot its producer as-of-now, so a reused temp slot
        binds each read to the producer live when it was read, not the last producer globally. */
    void RecordTerminalRead(UEdGraphPin* ReaderPin, TSharedPtr<FKismetTerminal> Terminal);
    class UK2Node_VariableGet* GetOrCreateVariableGetter(TSharedPtr<FKismetTerminal> Terminal);
    /** Struct-member READ (struct.Member): reconstruct as a UK2Node_BreakStruct on the struct value and return the
        member-named output pin. The read-side counterpart to the struct-member SET emitters. */
    class UK2Node_BreakStruct* GetOrCreateStructMemberBreak(TSharedPtr<FKismetTerminal> StructContextTerminal);
    TSharedPtr<FKismetTerminal> ResolvePassThrough(TSharedPtr<FKismetTerminal> Terminal) const;
    void ApplyLiteralToPin(const TSharedPtr<FKismetTerminal>& Terminal, UEdGraphPin* Pin);

    /** Container (array/set/map) LITERAL → a pure MakeArray/MakeSet/MakeMap node feeding Pin, because K2 forbids a
        literal default on a container pin outside IsPinDefaultValid's three exemptions (FunctionResult input /
        auto-create-ref-term / Interface BP). Only ever called when the schema has ALREADY rejected the default, so the
        pre-existing TrySetDefaultValue path is a proven no-op for these pins. Spawned with ZERO input pins (the only
        shape cooked bytecode produces — an empty ArrayConst); its wildcard output is typed by the existing Phase C.5
        PostReconstructNode pass from the OUTPUT link. Returns the output pin, or nullptr on soft-degrade (pin then
        left exactly as it is today). */
    UEdGraphPin* EmitContainerLiteralNode(const TSharedPtr<FKismetTerminal>& Terminal, UEdGraphPin* Pin);
    void WireExecFlow();
    UEdGraphPin* ResolveExecTarget(int32 StartIndex);
    UEdGraphPin* ResolveExecTarget(int32 StartIndex, TSet<int32>& Visited);
    bool IsSelfTerminal(const TSharedPtr<FKismetTerminal>& Terminal) const;

    /** The graph's single shared UK2Node_Self output pin (PN_Self), spawned lazily on first use.
        A REAL parameter pin that receives EX_Self (e.g. a library call's WorldContextObject) needs an EXPLICIT Self
        node: unlike the hidden self/target pin — which genuinely DOES default to self when left unconnected — an
        unconnected object PARAM does not; it compiles to (NoObject), a real semantic change (a null world context can
        fail at runtime). One node is shared per graph because ~20 calls per BP pass self this way.
        Returns nullptr on soft-degrade (caller then leaves the pin at its default == today's behaviour). */
    UEdGraphPin* GetOrCreateSelfNodeOutput();

    /** True if the UK2Node_VariableSet that will be reconstructed for SetStmt is going to RE-EMIT a FlushNetDormancy
        call of its own, which means the cooked FlushNetDormancy statement immediately PRECEDING it is compiler
        scaffolding and must be CONSUMED rather than reconstructed as its own call node (else it is emitted twice).
        Mirrors UK2Node_VariableSet::ShouldFlushDormancyOnSet(); the node itself cannot be asked, as it does not exist
        until the NEXT statement is processed. */
    bool WillRepSetReemitFlushNetDormancy(const TSharedPtr<FKismetCompiledStatement>& SetStmt);

    void ConnectMakeStructNodePinsWithTerminals(UK2Node* MakeStructNode, TSharedPtr<FKismetTerminal> StructTerminal);
    
    UEdGraphNode* CreateMakeMapNode();
    UEdGraphNode* CreateMakeSetNode();
    UEdGraphNode* CreateMakeArrayNode();

    UEdGraphNode* CreateCastNode(bool bIsMetaCast);
    /** Object↔interface conversion (KCST_CastObjToInterface/CastInterfaceToObj/CrossInterfaceCast) → a pure
        UK2Node_DynamicCast to the destination class. Returns its typed result pin (nullptr if the class is unresolved). */
    UEdGraphPin* EmitInterfaceCastNode(TSharedPtr<FKismetTerminal> DestClassLiteral, TSharedPtr<FKismetTerminal> SourceObject);
    UEdGraphNode* CreateAssignmentNode();
    UEdGraphNode* CreateMakeStructNode(TSharedPtr<FKismetTerminal> StructTerminal);
    UEdGraphNode* CreateSetFieldsInStructNode(TSharedPtr<FKismetTerminal> StructTerminal);
    UEdGraphNode* CreateStructMemberSetNode(TSharedPtr<FKismetTerminal> StructTerminal);
    UEdGraphNode* CreateCopyNode();
    UEdGraphNode* CreateDelegateSetNode();
    UEdGraphNode* CreateVariableSetNode();
    UEdGraphNode* CreateVariableSetByRefNode();
    UEdGraphNode* CreateMakeDelegateNode();
    UEdGraphNode* CreateMulticastDelegateNode(TSubclassOf<UK2Node_BaseMCDelegate> NodeClass);
    UEdGraphNode* CreateFunctionCallNode();
    /** Standalone object/interface → bool (KCST_ObjectToBool not paired with a DynamicCast): a pure
        UKismetSystemLibrary::IsValid call. Returns its bool ReturnValue output pin (nullptr on failure). */
    UEdGraphPin* EmitObjectIsValidNode(TSharedPtr<FKismetTerminal> SourceObject);
    /** Pre-pass: plan each FText::Format collapse (find the Format call + its MakeStruct/MakeArray constituents). */
    void DetectFormatTextPatterns();
    /** Emit a planned Format as one UK2Node_FormatText (the internal FFormatArgumentData chain can't compile). */
    UEdGraphNode* EmitFormatTextNode(const FFormatTextCollapsePlan& Plan);
    /** True if the call is UDataTableFunctionLibrary::GetDataTableRowFromName (the internal fn UK2Node_GetDataTableRow expands to). */
    bool IsGetDataTableRowCall(const TSharedPtr<FKismetCompiledStatement>& S) const;
    /** Reconstruct a GetDataTableRow call as a UK2Node_GetDataTableRow so its OutRow struct type self-resolves from the DataTable. */
    UEdGraphNode* CreateGetDataTableRowNode();
    /** Resolve the concrete UDataTable* a member-variable DataTable terminal refers to, from the owning class CDO
        default (null if literal/local/unresolvable) — lets a variable-sourced GetDataTableRow type its OutRow. */
    class UDataTable* ResolveMemberDataTableDefault(const TSharedPtr<FKismetTerminal>& DataTableTerminal);

    /** Authoritative OutRow row-struct for a GetDataTableRow: the cooked OutRow arg references a CONCRETE local
        variable whose struct type is the real row struct (independent of the DataTable literal/CDO, which may be
        null). Returns null if the terminal isn't a struct or is only the abstract FTableRowBase base. */
    class UScriptStruct* ResolveOutRowStructFromTerminal(const TSharedPtr<FKismetTerminal>& OutRowTerminal);
    
    UEdGraphNode* GenerateNodeForStatement();

    /** Returns true if local variable in question was created manually by the user and not auto generated by kismet compiler */
	bool IsUserCreatedLocalVariable(TSharedPtr<FKismetTerminal> Terminal) { return Terminal.IsValid() && Terminal->VarType == FKismetTerminal::EVarType_Local && !Terminal->AssociatedVarProperty.IsEmpty(); }

    /** Returns true if variable in question is a local variable, even if it is located in class but still considered local */
	bool IsLocalVariable(TSharedPtr<FKismetTerminal> Terminal) { return Terminal.IsValid() && Terminal->VarType == FKismetTerminal::EVarType_Local; }

    /** Resolves UStruct type of the provided context terminal object by analyzing it's type. Obviously only valid for terminals used as contexts */
    UStruct* ResolveContextTerminalType(TSharedPtr<FKismetTerminal> Terminal);

    /** Retrieves current statement from the list, possibly with an offset. Does not advance reader index */
    FORCEINLINE TSharedPtr<FKismetCompiledStatement> PeekStatement(int32 Offset = 0) {
        const int32 PeekIdx = CurrentStatementIndex + Offset; return CompiledStatements.IsValidIndex(PeekIdx) ? CompiledStatements[PeekIdx] : nullptr;
    }

    /** The next VALID (non-null) statement at or after CurrentStatementIndex+Offset, skipping the null slots that
     *  ProcessStatement leaves for editor-only Tracepoint/WireTracepoint opcodes (they are added to the statement
     *  list as nullptr, KismetBytecodeTransformer.cpp). Use this — never PeekStatement — to compute the FALL-THROUGH
     *  SUCCESSOR that a node's exec-out (Then) pin patches up to: cooked DDS2 bytecode interleaves a tracepoint
     *  between every real statement, so PeekStatement(0) almost always returns a null slot, the IsValid() guard skips
     *  the ExecPinPatchUpMap entry, and the exec link is silently lost (every branch/impure node loses its Then wire).
     *  ResolveExecTarget already threads through nulls by INDEX; this makes the by-statement patchup just as robust. */
    FORCEINLINE TSharedPtr<FKismetCompiledStatement> PeekNextValidStatement(int32 Offset = 0) {
        for (int32 Idx = CurrentStatementIndex + Offset; CompiledStatements.IsValidIndex(Idx); ++Idx)
            if (CompiledStatements[Idx].IsValid()) return CompiledStatements[Idx];
        return nullptr;
    }

    /** Retrieves current statement from the list and advances current statement index */
    FORCEINLINE TSharedPtr<FKismetCompiledStatement> PopStatement() {
        return CompiledStatements.IsValidIndex(CurrentStatementIndex) ? CompiledStatements[CurrentStatementIndex++] : nullptr;
    }

    /** Retrieves first kismet graph node with provided class and asserts if it's not found */
    template<typename T>
    FORCEINLINE T* FindFirstGraphNodeOfClass() {
        TArray<T*> FoundKismetNodes;
        EditorGraph->GetNodesOfClass<T>(FoundKismetNodes);
        check(FoundKismetNodes.Num());
        return FoundKismetNodes[0];
    }
    
    /** Function we are currently reconstructing code for */
    UFunction* Function;

    /** Blueprint owner of this graph */
    UBlueprint* OwnerBlueprint;
    /** Graph containing source code for edited function */
    UEdGraph* EditorGraph;
    
    /** Collection of statements we are decompiling */
    TArray<TSharedPtr<FKismetCompiledStatement>> CompiledStatements;
    int32 CurrentStatementIndex;

    /** Map of intermediate variable terminals to node outputs which caused their generation */
    TMap<FKismetTerminalAsKeyType, UEdGraphPin*> IntermediateVariableHandles;

    /** Per-read snapshot: reader input pin -> the specific producer output pin that was live when the read was
        recorded. Disambiguates reused temp slots (e.g. two Map_Find calls both writing CallFunc_Map_Find_Value). */
    TMap<UEdGraphPin*, UEdGraphPin*> IntermediateSnapshotByReader;

    /** After code generation, pin specified as the key will be automatically connected to the input exec pin of the value node */
    TMap<UEdGraphPin*, TSharedPtr<FKismetCompiledStatement>> ExecPinPatchUpMap;

    /** Map of pins to connect to terminals after all nodes have been generated */
    TMap<UEdGraphPin*, TSharedPtr<FKismetTerminal>> TerminalPatchUpMap;

    /** Map of the statement into the input exec pin of node generated by it */
    TMap<TSharedPtr<FKismetCompiledStatement>, UEdGraphPin*> NodeExecPinInputMap;

    /** For each KCST_EndOfThread / KCST_EndOfThreadIfNot, the statement its flow-stack pop jumps to (loop-back or
        structured return), computed by ResolveFlowStackTargets(). */
    TMap<TSharedPtr<FKismetCompiledStatement>, TSharedPtr<FKismetCompiledStatement>> FlowStackPopTarget;

    /** Terminal specified as the key is the same thing as the terminal specified as value, and value terminal should be actually used for key code generation */
    TMap<FKismetTerminalAsKeyType, TSharedPtr<FKismetTerminal>> PassThroughTerminals;

    /** Map of create delegate nodes to patch up after terminals have been connected */
    TMap<UK2Node_CreateDelegate*, FName> CreateDelegatePatchUpMap;

    // ---- EVENT MODE state (SetEventContext) — configuration, NOT per-run state: set before Run(), never reset
    //      by it. One decompiler instance is constructed per event, so nothing leaks between events. ----
    bool bEventMode = false;
    class UK2Node* EventEntryNode = nullptr;
    TMap<FName, FName> FrameParamMap;      // ubergraph frame property -> event node output pin name
    int32 EntryStatementIndex = 0;         // the exec root; 0 on the function path (its first statement IS the entry)
    TArray<int32> InitialFlowStack;        // [B] slice-relative statement indices; NOT empty when the prologue pushes

    // ---- PHASE 3 driver state ----
    class UK2Node_FunctionEntry* EntryNode = nullptr;
    class UK2Node_FunctionResult* ResultNode = nullptr;
    UEdGraphPin* EntryThenPin = nullptr;
    UEdGraphPin* ResultExecPin = nullptr;
    TMap<FName, UEdGraphPin*> ParamOutputPinByName;   // entry: input-param name -> output data pin
    TMap<FName, UEdGraphPin*> ReturnInputPinByName;   // result: out-param name -> input data pin
    /** Out-param assignment counts by name (ScanOutParamAssignCounts). A name assigned EXACTLY once collapses: no
        local, no Set/Get node — the value feeds the FunctionResult input pin directly, recompiling to the cooked
        `Let(OutParam = value)` byte-for-byte. 0 or 2+ keeps the reconstructed local (branch-correct, one extra
        statement of drift). Deliberately a SUPERSET keyed on name only — see MifOutParamWriteName. */
    TMap<FName, int32> OutParamAssignCount;
    /** True if OutName is assigned exactly once in the whole function ⇒ its local is provably unnecessary. This is the
        SOLE collapse test, shared by EstablishTerminators (skip the local) and the three pass-1 assignment sites (skip
        the Set node), so the two can never disagree and strand a Set node on a local that was never created. */
    bool IsSingleAssignOutParam(FName OutName) const { return OutParamAssignCount.FindRef(OutName) == 1; }
    /** True if OutName is NEVER assigned in the whole function ⇒ it stays at its native zero-default. Cooked bytecode
        emits NOTHING for such an out-param (it relies on frame zero-init and just returns) — an empty interface stub is
        the canonical case (`Return(Nothing)`). The reconstructed local model would instead mint a local + a Get feeding
        the Return pin from an uninitialised %L slot → a spurious `Let(OutParam = local)` per never-assigned out-param
        (the largest single corpus drift bucket). Leave these pins entirely alone: no local, no Get, no wiring → the
        Result pin keeps its signature default and recompiles to the bare `Return`. Value-identical to the zero-default
        cooked relies on. */
    bool IsNeverAssignedOutParam(FName OutName) const { return OutParamAssignCount.FindRef(OutName) == 0; }
    TMap<FKismetTerminalAsKeyType, class UK2Node_VariableGet*> VariableGetterCache;
    /** The ONE shared UK2Node_Self for this graph (see GetOrCreateSelfNodeOutput). Per-run state — reset in Run()
        alongside the other caches, so a node from a previously reconstructed graph is never reused. */
    class UK2Node_Self* SelfNodeCache = nullptr;
    // struct-context terminal -> the single BreakStruct that breaks it (a BreakStruct is not a UK2Node_VariableGet).
    TMap<FKismetTerminalAsKeyType, class UK2Node_BreakStruct*> StructMemberBreakCache;
    // FText::Format collapse: statements consumed by a planned collapse (skipped in pass-1) + the plan per trigger call.
    TSet<const FKismetCompiledStatement*> FormatTextConsumedStmts;
    TMap<const FKismetCompiledStatement*, FFormatTextCollapsePlan> FormatTextPlans;
    // GetDataTableRow nodes whose DataTable is a member-variable read: row struct resolved from the source-class CDO
    // default, stamped onto OutRow in Phase B.5 (Phase D skips these so the stamp survives to compile).
    TMap<class UK2Node_GetDataTableRow*, class UScriptStruct*> DataTableRowStructByNode;
    TMap<TSharedPtr<FKismetCompiledStatement>, int32> StatementIndexMap;
    class UEdGraphSchema_K2* K2Schema = nullptr;
    int32 FailureCount = 0;
    bool bDegraded = false;
    int32 NextNodePosX = 320;
    int32 NodesCreated = 0;
    int32 StatementsProcessed = 0;
    // Running Y for stacked degrade-reason comment nodes (EmitFailureComment). Reset per graph in Run().
    int32 FailureCommentPosY = 700;
};
