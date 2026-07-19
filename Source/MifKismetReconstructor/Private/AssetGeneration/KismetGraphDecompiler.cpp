#include "AssetGeneration/KismetGraphDecompiler.h"
#include "MifReconstructorDebug.h"
#include "Kismet2/BlueprintEditorUtils.h"
#include "EdGraphSchema_K2_Actions.h"
#include "K2Node_CallFunction.h"
#include "K2Node_CallArrayFunction.h"
#include "K2Node_AddDelegate.h"
#include "K2Node_CallParentFunction.h"
#include "K2Node_ClassDynamicCast.h"
#include "K2Node_ClearDelegate.h"
#include "K2Node_Copy.h"
#include "K2Node_CreateDelegate.h"
#include "K2Node_DynamicCast.h"
#include "K2Node_VariableSet.h"
#include "K2Node_MakeArray.h"
#include "K2Node_MakeMap.h"
#include "K2Node_MakeSet.h"
#include "K2Node_MakeStruct.h"
#include "K2Node_RemoveDelegate.h"
#include "K2Node_SetFieldsInStruct.h"
#include "K2Node_StructMemberGet.h"
#include "K2Node_VariableSetRef.h"
#include "Kismet/KismetSystemLibrary.h"
#include "K2Node_GetDataTableRow.h"
#include "Kismet/DataTableFunctionLibrary.h"
#include "Engine/DataTable.h"
#include "UObject/UnrealType.h"

FKismetGraphDecompiler::FKismetGraphDecompiler(UFunction* Function, UEdGraph* Graph) {
    this->Function = Function;
    this->EditorGraph = Graph;
}

void FKismetGraphDecompiler::Initialize(const TArray<TSharedPtr<FKismetCompiledStatement>>& Statements) {
    this->CompiledStatements = Statements;
}

UEdGraphNode* FKismetGraphDecompiler::CreateMakeMapNode() {
    TSharedPtr<FKismetCompiledStatement> Statement = PopStatement();
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();
    
    //Spawn node in question and links it's terms with children nodes
    UK2Node_MakeMap* MakeMapNode = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_MakeMap>(EditorGraph, NodePosition, EK2NewNodeFlags::None,
        [&Statement](UK2Node_MakeMap* MakeMapNode) {
        //Setup number of outputs so AllocateDefaultPins will create correct amount of pins
        //We divide number of right hand inputs by two because NumInputs is actually a number of (key, value) pairs
        MakeMapNode->NumInputs = Statement->RHS.Num() / 2;
    });

    //Connect inputs terminals and generate nodes for them
    //First input pin is offset by one because first pin allocated by MakeMap is an output
    for (int32 i = 0; i < Statement->RHS.Num(); i++) {
        //NumInputs = RHS/2, so an ODD RHS from malformed cooked bytecode allocates fewer pins than this loop reads →
        //Pins[1+i] would index out of bounds (a crash BEFORE the old Direction check ran). Bound-check and stop
        //wiring instead; a wrong-direction pin (never expected on our own freshly-spawned node) degrades the same way.
        if (!MakeMapNode->Pins.IsValidIndex(1 + i)) break;
        UEdGraphPin* MakeMapInputPin = MakeMapNode->Pins[1 + i];
        if (MakeMapInputPin->Direction != EEdGraphPinDirection::EGPD_Input) break;

        const TSharedPtr<FKismetTerminal> InputTerminalValue = Statement->RHS[i];
        this->RecordTerminalRead(MakeMapInputPin, InputTerminalValue);
    }

    //Link output pin with intermediate variable value for replacement
    UEdGraphPin* OutputMakeMapPin = MakeMapNode->Pins[0];
    this->IntermediateVariableHandles.Add(Statement->LHS, OutputMakeMapPin);
    return MakeMapNode;
}

UEdGraphNode* FKismetGraphDecompiler::CreateMakeSetNode() {
    TSharedPtr<FKismetCompiledStatement> Statement = PopStatement();
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();
    
    //Spawn node in question and links it's terms with children nodes
    UK2Node_MakeSet* MakeSetNode = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_MakeSet>(EditorGraph, NodePosition, EK2NewNodeFlags::None,
        [&Statement](UK2Node_MakeSet* MakeSetNode) {
        //Setup number of outputs so AllocateDefaultPins will create correct amount of pins
        MakeSetNode->NumInputs = Statement->RHS.Num();
    });

    //Connect inputs terminals and generate nodes for them
    //First input pin is offset by one because first pin allocated by MakeMap is an output
    for (int32 i = 0; i < Statement->RHS.Num(); i++) {
        //Bound-check the pin index (see CreateMakeMapNode) so short/malformed cooked RHS degrades instead of OOB-crashing.
        if (!MakeSetNode->Pins.IsValidIndex(1 + i)) break;
        UEdGraphPin* MakeSetInputPin = MakeSetNode->Pins[1 + i];
        if (MakeSetInputPin->Direction != EEdGraphPinDirection::EGPD_Input) break;

        const TSharedPtr<FKismetTerminal> InputTerminalValue = Statement->RHS[i];
        this->RecordTerminalRead(MakeSetInputPin, InputTerminalValue);
    }

    //Link output pin with intermediate variable value for replacement
    UEdGraphPin* OutputMakeSetPin = MakeSetNode->Pins[0];
    this->IntermediateVariableHandles.Add(Statement->LHS, OutputMakeSetPin);
    return MakeSetNode;
}

UEdGraphNode* FKismetGraphDecompiler::CreateMakeArrayNode() {
    TSharedPtr<FKismetCompiledStatement> Statement = PopStatement();
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();
    
    //Spawn node in question and links it's terms with children nodes
    UK2Node_MakeArray* MakeArrayNode = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_MakeArray>(EditorGraph, NodePosition, EK2NewNodeFlags::None,
        [&Statement](UK2Node_MakeArray* MakeArrayNode) {
        //Setup number of outputs so AllocateDefaultPins will create correct amount of pins
        MakeArrayNode->NumInputs = Statement->RHS.Num();
    });

    //Connect inputs terminals and generate nodes for them
    //First input pin is offset by one because first pin allocated by MakeMap is an output
    for (int32 i = 0; i < Statement->RHS.Num(); i++) {
        //Bound-check the pin index (see CreateMakeMapNode) so short/malformed cooked RHS degrades instead of OOB-crashing.
        if (!MakeArrayNode->Pins.IsValidIndex(1 + i)) break;
        UEdGraphPin* MakeArrayInputPin = MakeArrayNode->Pins[1 + i];
        if (MakeArrayInputPin->Direction != EEdGraphPinDirection::EGPD_Input) break;

        const TSharedPtr<FKismetTerminal> InputTerminalValue = Statement->RHS[i];
        this->RecordTerminalRead(MakeArrayInputPin, InputTerminalValue);
    }

    //Link output pin with intermediate variable value for replacement
    UEdGraphPin* OutputMakeArrayPin = MakeArrayNode->Pins[0];
    this->IntermediateVariableHandles.Add(Statement->LHS, OutputMakeArrayPin);
    return MakeArrayNode;
}

UEdGraphNode* FKismetGraphDecompiler::CreateCastNode(bool bIsMetaCast) {
    TSharedPtr<FKismetCompiledStatement> Statement = PopStatement();
    //First RHS terminal will always be a class constant specifying type of class to cast to
    if (Statement->RHS.Num() < 2) return NULL;   // soft-degrade a malformed cast
    const TSharedPtr<FKismetTerminal> ClassToCastTerminal = Statement->RHS[0];
    UClass* ClassObjectToCast = ClassToCastTerminal.IsValid() ? Cast<UClass>(ClassToCastTerminal->ObjectLiteral) : nullptr;
    if (!ClassObjectToCast) return NULL;

    const TSharedPtr<FKismetTerminal> InputObjectTerminal = Statement->RHS[1];
    const TSharedPtr<FKismetTerminal> CastedObjectOutVariableName = Statement->LHS;
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();

    //K2Node_DynamicCast will always emit KCST_ObjectToBool as the next statement
    //Variable name generated by it should be wired up with DynamicCast bSuccess pin output instead
    const TSharedPtr<FKismetCompiledStatement> ObjectToBool = PopStatement();
    if (!ObjectToBool.IsValid() || ObjectToBool->Type != ECompiledStatementType::KCST_ObjectToBool) return NULL;
    const TSharedPtr<FKismetTerminal> CastSucceedOutVariableName = ObjectToBool->LHS;

    //Next statement decides whenever cast is pure or not
    //When cast is not pure, next statements will be KCST_GotoIfNot followed by KCST_UnconditionalGoto
    //with GotoIfNot LHS being equal to CastSucceedOutVariableName
    const TSharedPtr<FKismetCompiledStatement> GotoIfNot = PeekStatement();

    bool bIsCastCompletelyPure = true;
    TSharedPtr<FKismetCompiledStatement> StatementToJumpOnFailure;
    TSharedPtr<FKismetCompiledStatement> StatementToJumpOnSuccess;
    
    if (GotoIfNot.IsValid() && GotoIfNot->Type == ECompiledStatementType::KCST_GotoIfNot
        && GotoIfNot->LHS.IsValid() && CastSucceedOutVariableName.IsValid() && GotoIfNot->LHS->operator==(*CastSucceedOutVariableName)) {
        //Pop GotoIfNot from statement list
        PopStatement();
        
        //This is an impure cast, next statement checks if bSuccess is false and then jumps to false execution statements!
        bIsCastCompletelyPure = false;

        //Next statement generated will be UnconditionalGoto to the success branch
        //But it can be removed during optimization if it jumps just to the next statement
        //so if the next statement is UnconditionalGoto, we Pop it and wire up directly
        //otherwise we just peek it and wire up next statement
        const TSharedPtr<FKismetCompiledStatement> UnconditionalGoto = PeekStatement();

        //Next statement is unconditional goto, Statement to jump on success is it's label
        //(null successor — a dangling/degraded next statement or end-of-stream — falls through to the else, where
        // the null target degrades cleanly via the StatementIndexMap.Find(-1) path in pass-2; don't deref null here)
        if (UnconditionalGoto.IsValid() && UnconditionalGoto->Type == ECompiledStatementType::KCST_UnconditionalGoto) {
            PopStatement(); //Pop unconditional goto because it is unnecessary
            StatementToJumpOnSuccess = UnconditionalGoto->TargetLabel;
        } else {
            //Next statement is not an unconditional goto, so success branch is just following
            //statement list directly without any jumps
            StatementToJumpOnSuccess = UnconditionalGoto;
        }
        
        StatementToJumpOnFailure = GotoIfNot->TargetLabel;
    }
    
    UK2Node_DynamicCast* DynamicCastNode;
    auto NodeInitializerLambda = [bIsCastCompletelyPure, ClassObjectToCast](UK2Node_DynamicCast* DynamicCastNode) {
        //We know at this point whenever cast is going to be pure or impure
        DynamicCastNode->TargetType = ClassObjectToCast;
        DynamicCastNode->SetPurity(bIsCastCompletelyPure);
    };

    if (bIsMetaCast) {
        //For MetaCast, spawn ClassDynamicCast node
        DynamicCastNode = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_ClassDynamicCast>(EditorGraph, NodePosition, EK2NewNodeFlags::None, NodeInitializerLambda);
    } else {
        //Otherwise spawn normal K2Node_DynamicCast
        DynamicCastNode = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_DynamicCast>(EditorGraph, NodePosition, EK2NewNodeFlags::None, NodeInitializerLambda);
    }

    //Connect input object pin with the terminal type passed at RHS
    UEdGraphPin* InputObject = DynamicCastNode->GetCastSourcePin();
    this->RecordTerminalRead(InputObject, InputObjectTerminal);

    //Add output object pin into the variable map so it will be connected later
    UEdGraphPin* OutputObjectPin = DynamicCastNode->GetCastResultPin();
    this->IntermediateVariableHandles.Add(CastedObjectOutVariableName, OutputObjectPin);

    //Future actions depend on whenever we are working with pure or an impure cast
    if (bIsCastCompletelyPure) {
        //For pure casts, we also need to add bSuccess pin into the intermediate variable map
        UEdGraphPin* CastSucceedOutputPin = DynamicCastNode->GetBoolSuccessPin();
        this->IntermediateVariableHandles.Add(CastSucceedOutVariableName, CastSucceedOutputPin);
    } else {
        //For impure casts, we need to connect input pin and add output pins to fixup map
        UEdGraphPin* InputExecPin = DynamicCastNode->FindPinChecked(UEdGraphSchema_K2::PN_Execute, EEdGraphPinDirection::EGPD_Input);
        this->NodeExecPinInputMap.Add(Statement, InputExecPin);

        //Automatically connect success and failure execution pins later
        UEdGraphPin* OutputSuccessExecPin = DynamicCastNode->GetValidCastPin();
        UEdGraphPin* OutputFailureExecPin = DynamicCastNode->GetInvalidCastPin();

        this->ExecPinPatchUpMap.Add(OutputSuccessExecPin, StatementToJumpOnSuccess);
        this->ExecPinPatchUpMap.Add(OutputFailureExecPin, StatementToJumpOnFailure);
    }
    
    return DynamicCastNode;
}

// Object↔interface conversion reconstructed as a PURE UK2Node_DynamicCast to the destination class. Needed because a
// raw object wired into a strict interface Target pin is rejected by the schema (only interface→object autocasts), so
// a dataflow pass-through leaves an incompatible link. Returns the typed result pin (PC_Interface, or PC_Object for
// InterfaceToObj); nullptr degrades to the caller's pass-through fallback.
UEdGraphPin* FKismetGraphDecompiler::EmitInterfaceCastNode(
    TSharedPtr<FKismetTerminal> DestClassLiteral, TSharedPtr<FKismetTerminal> SourceObject) {
    UClass* DestClass = DestClassLiteral.IsValid() ? Cast<UClass>(DestClassLiteral->ObjectLiteral) : nullptr;
    if (!DestClass || !SourceObject.IsValid()) return nullptr;
    UK2Node_DynamicCast* Cast = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_DynamicCast>(
        EditorGraph, FVector2D(NextNodePosX, 300.0), EK2NewNodeFlags::None,
        [DestClass](UK2Node_DynamicCast* N){ N->TargetType = DestClass; N->SetPurity(true); });
    if (!Cast) return nullptr;
    ++NodesCreated; Cast->NodePosX = NextNodePosX; NextNodePosX += 220;
    if (UEdGraphPin* Src = Cast->GetCastSourcePin()) RecordTerminalRead(Src, SourceObject);   // wildcard → retyped in Phase D
    return Cast->GetCastResultPin();
}

UEdGraphNode* FKismetGraphDecompiler::CreateAssignmentNode() {
    const TSharedPtr<FKismetCompiledStatement> Statement = PeekStatement();
    
    //KCST_Assignment can be generated when:
    // 1) through FKismetCompilerUtilities::CreateObjectAssignmentStatement call
    //     (which can also generate KCST_CastObjToInterface/KCST_CastInterfaceToObj instead, but they both will end up here too)
    //     Can be also called by:
    //         a) by K2Node_MakeStruct for actually filling struct fields X
    //                 - Actually MakeStruct has a child node - StructMemberSet, this node is impure and can set individual struct values of local variable directly
    //         b) by K2Node_VariableSet for setting user defined variable value
    //         c) by K2Node_Copy for copying provided value into the local generated variable X
    // 2) by K2Node_MakeStruct for doing very awkward stuff with EditCondition properties X
    // 3) by K2Node_VariableSetRef to assign external variable passed by reference to the given value 
    // 4) by K2Node_SetFieldsInStruct if input struct is not passed by reference to copy it to the returned variable X
    // 5) by K2Node_MultiGate for implementing god knows what N
    // 6) by K2Node_DelegateSet for initializing delegate object with InstanceDelegate on self with provided function name
    // And we need to handle all of these cases... oh well...

    const TSharedPtr<FKismetTerminal> VariableAssigned = Statement->LHS;

    //Only and only K2Node_SetFieldsAndStruct and K2Node_MakeStruct can set struct variables directly
    //there is no way to modify them around these nodes in blueprints through assignment (except MAYBE through BreakStruct + SetVariableByRef)
    //but that case should be handled below if it is even possible
    if (VariableAssigned->Context && VariableAssigned->Context->ContextType == FKismetTerminal::EContextType_Struct) {
        const TSharedPtr<FKismetTerminal> Context = VariableAssigned->Context;
        //ContextType and PinCategory are independent fields that can legitimately disagree on cooked bytecode (the
        //object/class-context read path already soft-degrades this exact mismatch, ~line 1208). Degrade the assignment
        //rather than assert; the driver's no-progress guard force-advances a null return from this Peek-based emitter.
        if (Context->Type.PinCategory != UEdGraphSchema_K2::PC_Struct) {
            EmitFailureComment(TEXT("assignment struct-context PinCategory mismatch (deferred)"));
            return NULL;
        }

        //If it is a local variable, it should not have a context
        if (IsLocalVariable(Context)) {
            //MakeStruct temps ALWAYS carry a recognizable name ("K2Node_MakeStruct…", e.g. FFormatArgumentData for
            //FormatText args). This MUST be tested BEFORE IsUserCreatedLocalVariable(): in this port AssociatedVarProperty
            //is a NAME (never empty), so IsUserCreatedLocalVariable() is true for compiler temps too — the name is the
            //only reliable discriminator. (Old order mis-routed the temp to CreateStructMemberSetNode → FindLocalVariable
            //missed → EmitFailureComment WITHOUT advancing → per-member "made no progress" churn that degraded the whole fn.)
            if (Context->AssociatedVarProperty.StartsWith(TEXT("K2Node_MakeStruct"))) {
                return CreateMakeStructNode(Context);
            }

            //A genuine user-declared struct local → set its fields directly (SetFieldsInStruct / StructMemberSet).
            //This node has no data input for a self target, so it only works for locals.
            if (IsUserCreatedLocalVariable(Context)) {
                return CreateStructMemberSetNode(Context);
            }
        }

        //We have a context, and only thing able to handle this so far is SetFieldsInStruct node,
        //which can basically accept any external Terminal as an input pin and will perform operations on it
        //so theoretically it can handle something like SetFieldsInStruct(Object->Object2->Variable)
        return CreateSetFieldsInStructNode(VariableAssigned);
    }

    //Local variables are pretty easy to handle
    if (IsLocalVariable(VariableAssigned)) {
        const FString LocalVariableName = VariableAssigned->AssociatedVarProperty;
        
        //If we are working with a local variable with copy name, we are definitely working with a K2Node_Copy
        if (LocalVariableName.StartsWith(TEXT("K2Node_Copy_ReturnValue"))) {
            return CreateCopyNode();
        }
        //K2Node_DelegateSet will result in a local variable with a recognisable name too
        if (LocalVariableName.StartsWith(TEXT("K2Node_DelegateSet"))) {
            return CreateDelegateSetNode();
        }
    }

    //Only remaining nodes are K2Node_VariableSet and K2Node_VariableSetRef
    //Difference between them is very simple: VariableSet sets "static" variable predefined earlier,
    //while VariableSetRef can set any unknown value passed by reference to the provided value
    //Solution here would be using VariableSet when possible, while falling back to
    //VariableSetRef when variable expression in question cannot be represented as a static variable reference
    
    //User-defined local variable assignments can always be expressed through VariableSet node
    if (IsUserCreatedLocalVariable(VariableAssigned)) {
        return CreateVariableSetNode();
    }

    //Variables in object context where object type is known can be expressed by VariableSet too
    if (VariableAssigned->Context && VariableAssigned->Context->ContextType == FKismetTerminal::EContextType_Object) {
        const TSharedPtr<FKismetTerminal> Context = VariableAssigned->Context;
        //As above: ContextType==Object with a non-Object PinCategory is a cooked-bytecode inconsistency, not a
        //programmer invariant — degrade instead of asserting. CreateVariableSetNode would itself degrade downstream,
        //but bailing here avoids feeding it a type-inconsistent terminal.
        if (Context->Type.PinCategory != UEdGraphSchema_K2::PC_Object) {
            EmitFailureComment(TEXT("assignment object-context PinCategory mismatch (deferred)"));
            return NULL;
        }

        return CreateVariableSetNode();
    }

    //No idea otherwise, try to use VariableSetByRef node to set non-local variable or variable 
    //Self-member instance variable (no explicit context) → a normal VariableSet on self.
    if (VariableAssigned->VarType == FKismetTerminal::EVarType_Instanced) {
        return CreateVariableSetNode();
    }

    return CreateVariableSetByRefNode();
}

void FKismetGraphDecompiler::ConnectMakeStructNodePinsWithTerminals(UK2Node* MakeStructNode, TSharedPtr<FKismetTerminal> StructTerminal) {
    
    //Checks whenever given statement is basically an assignment in the generated struct context
    const TFunction<bool(TSharedPtr<FKismetCompiledStatement>)> IsMakeStructAssignStatement = [&](const TSharedPtr<FKismetCompiledStatement> Statement){
        if (!Statement.IsValid()) return false;   // end-of-list peek returns invalid
        //Casts can replace normal assignments node if object is implicitly casted to interface or vice versa
        //They will still have all properties of the normal assignment statement though
        if (Statement->Type == ECompiledStatementType::KCST_Assignment ||
            Statement->Type == ECompiledStatementType::KCST_CastObjToInterface ||
            Statement->Type == ECompiledStatementType::KCST_CastInterfaceToObj) {
            const TSharedPtr<FKismetTerminal> LeftHandOperand = Statement->LHS;

            //Left hand terminal should have a context and it should be a struct type
            if (LeftHandOperand.IsValid() && LeftHandOperand->Context && LeftHandOperand->Context->ContextType == FKismetTerminal::EContextType_Struct) {
                const TSharedPtr<FKismetTerminal> LeftHandContext = LeftHandOperand->Context;
                //Context of the call should be equal to the struct terminal we are using
                return LeftHandContext->operator==(*StructTerminal);
            }
        }
        
        return false;
    };

    //A pure inline conversion writing a value member directly: KCST_CallFunction whose LHS is a struct-member context
    //on THIS struct (e.g. `Let StructTemp.ArgumentValueInt = CallMath Conv_IntToInt64(src)` for a FormatText int arg).
    const TFunction<bool(TSharedPtr<FKismetCompiledStatement>)> IsMakeStructInlineCallStatement = [&](const TSharedPtr<FKismetCompiledStatement> Statement){
        if (!Statement.IsValid() || Statement->Type != ECompiledStatementType::KCST_CallFunction) return false;
        const TSharedPtr<FKismetTerminal> L = Statement->LHS;
        return L.IsValid() && L->Context.IsValid()
            && L->Context->ContextType == FKismetTerminal::EContextType_Struct
            && L->Context->operator==(*StructTerminal);
    };

    //Iterate through all following assignment statements
    while (true) {
        //Peek pins as long as we encounter assignments to the struct terminal
        const TSharedPtr<FKismetCompiledStatement> NextStatement = PeekStatement();
        const bool IsMakeStructAssignmentBool = IsMakeStructAssignStatement(NextStatement);

        //This is a MakeStruct assignment, read property name from left side and expression from the right side
        if (IsMakeStructAssignmentBool) {
            if (!NextStatement->LHS.IsValid() || NextStatement->RHS.Num() == 0) { PopStatement(); continue; }
            const FString StructPropertyName = NextStatement->LHS->AssociatedVarProperty;
            const TSharedPtr<FKismetTerminal> RightHandValue = NextStatement->RHS[0];
            UEdGraphPin* PropertyPin = MakeStructNode->FindPin(*StructPropertyName, EGPD_Input);
            //A struct field with no matching exposed pin (editor-only/renamed/optional-hidden) → skip it, don't crash.
            if (!PropertyPin) { PopStatement(); continue; }

            //Connect terminal to the property pin of the structure
            this->RecordTerminalRead(PropertyPin, RightHandValue);

            //Pop statement that we just handled from the list
            PopStatement();
        } else if (IsMakeStructInlineCallStatement(NextStatement)) {
            //A pure inline conversion writes a value member as a CallFunction whose LHS is a struct-member context on
            //THIS struct. CreateFunctionCallNode pops it (always advances), spawns the Conv node, and registers
            //IntermediateVariableHandles[LHS]=ReturnValue; then bind the MakeStruct member input to read that value
            //(RecordTerminalRead snapshots the Conv output so pass-2 wires the member pin ← ReturnValue).
            const FString StructPropertyName = NextStatement->LHS->AssociatedVarProperty;
            const TSharedPtr<FKismetTerminal> MemberTerm = NextStatement->LHS;
            UEdGraphNode* CallNode = CreateFunctionCallNode();
            if (CallNode) { ++NodesCreated; CallNode->NodePosX = NextNodePosX; NextNodePosX += 220; }
            if (UEdGraphPin* PropertyPin = MakeStructNode->FindPin(*StructPropertyName, EGPD_Input))
                this->RecordTerminalRead(PropertyPin, MemberTerm);
        } else {
            //That statement is not related to the struct, remove it
            //All struct set statements will be generated in a row, followed by simple goto pulse to the next node
            break;
        }
    }
}

UEdGraphNode* FKismetGraphDecompiler::CreateMakeStructNode(TSharedPtr<FKismetTerminal> StructTerminal) {
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();
    
    //Struct terminal should always have a struct context and a well-defined struct type
    if (StructTerminal->ContextType != FKismetTerminal::EContextType_Struct) return NULL;

    //Determine ScriptStruct object by looking at the type of the struct terminal.
    UScriptStruct* ScriptStruct = Cast<UScriptStruct>(StructTerminal->Type.PinSubCategoryObject);
    if (!ScriptStruct) return NULL;

    //Allocate node and connect pins that have statements associated with them
    UK2Node_MakeStruct* MakeStructNode = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_MakeStruct>(EditorGraph, NodePosition, EK2NewNodeFlags::None,
        [ScriptStruct](UK2Node_MakeStruct* MakeStructNode){
        MakeStructNode->StructType = ScriptStruct;
    });

    //Connect input pins with terminals associated with them
    ConnectMakeStructNodePinsWithTerminals(MakeStructNode, StructTerminal);

    //MakeStruct is a pure node, connect output structure parameter to the generated variable map
    UEdGraphPin* OutputStructPin = MakeStructNode->FindPin(ScriptStruct->GetFName(), EGPD_Output);
    if (OutputStructPin)
    {
        //struct-CONTEXT key: consumed by struct-member READS of this temp (GetOrCreateStructMemberBreak → BreakStruct).
        this->IntermediateVariableHandles.Add(StructTerminal, OutputStructPin);

        //ALSO register a plain-local VALUE-form key. The compiler reads a MakeStruct temp (e.g. a FormatText
        //FFormatArgumentData arg feeding a Make Array) as a plain EX_LocalVariable → ContextType_Object, which is NOT
        //value-equal to StructTerminal (operator== compares ContextType). Without this the SetArray element read misses
        //IntermediateVariableHandles and falls to the local-getter branch → spurious Local_ VariableGet + undetermined type.
        if (StructTerminal->VarType == FKismetTerminal::EVarType_Local
            && StructTerminal->ContextType == FKismetTerminal::EContextType_Struct)
        {
            TSharedPtr<FKismetTerminal> ValueKey = MakeShareable(new FKismetTerminal(*StructTerminal));
            ValueKey->ContextType = FKismetTerminal::EContextType_Object;   //plain-local read form
            ValueKey->Context.Reset();                                      //a local temp read carries no context
            this->IntermediateVariableHandles.Add(FKismetTerminalAsKeyType(ValueKey), OutputStructPin);
        }
    }
    return MakeStructNode;
}

UEdGraphNode* FKismetGraphDecompiler::CreateSetFieldsInStructNode(TSharedPtr<FKismetTerminal> StructTerminal) {
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();
    
    if (StructTerminal->ContextType != FKismetTerminal::EContextType_Struct) return NULL;
    UScriptStruct* StructType = Cast<UScriptStruct>(StructTerminal->Type.PinSubCategoryObject);
    if (!StructType) return NULL;

    //Allocate node and connect pins that have statements associated with them
    UK2Node_SetFieldsInStruct* SetFieldsInStruct = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_SetFieldsInStruct>(EditorGraph, NodePosition, EK2NewNodeFlags::None,
        [StructType](UK2Node_SetFieldsInStruct* MemberSetNode){
        MemberSetNode->StructType = StructType;
    });

    //Record first statement related to struct member set - it will be jumped to from previous node
    const TSharedPtr<FKismetCompiledStatement> FirstStatement = PeekStatement();

    //Connect input pins with terminals associated with them
    //It will work for SetFieldsInStruct because pin names are exactly the same between all struct handling nodes
    ConnectMakeStructNodePinsWithTerminals(SetFieldsInStruct, StructTerminal);

    const TSharedPtr<FKismetCompiledStatement> LastStatement = PeekStatement();

    //Associate input pin with the connected terminal
    UEdGraphPin* InputStructPin = SetFieldsInStruct->FindPinChecked(TEXT("StructRef"), EGPD_Input);
    UEdGraphPin* OutputStructPin = SetFieldsInStruct->FindPinChecked(TEXT("StructOut"), EGPD_Output);

    //Connect input pin to the input terminal
    this->RecordTerminalRead(InputStructPin, StructTerminal);

    //SetFieldsInStruct can end with KCST_Assignment statement assigning value to output terminal
    //It will contain struct input terminal as the right side expression, so we can detect it
    //Left side will also contain local variable named in a special way    
    if (LastStatement->Type == ECompiledStatementType::KCST_Assignment) {
        const TSharedPtr<FKismetTerminal> LeftSideTerminal = LastStatement->LHS;
        
        if (IsLocalVariable(LeftSideTerminal) && LeftSideTerminal->AssociatedVarProperty.StartsWith(TEXT("K2Node_SetFieldsInStruct_StructOut"))
            && LastStatement->RHS.Num() > 0 && LastStatement->RHS[0].IsValid() && LastStatement->RHS[0]->operator==(*StructTerminal)) {
            //Connect output pin to the leftside terminal we are handling
            this->IntermediateVariableHandles.Add(LeftSideTerminal, OutputStructPin);
            
            //Pop statement
            PopStatement();
        }
    }
    
    //Since this is an impure node, we need to record input and output pins
    UEdGraphPin* InputExecPin = SetFieldsInStruct->FindPinChecked(UEdGraphSchema_K2::PN_Execute, EEdGraphPinDirection::EGPD_Input);
    this->NodeExecPinInputMap.Add(FirstStatement, InputExecPin);

    //This node does not perform any jumps on it's own, so it will just execute next statement in the instruction list
    UEdGraphPin* OutputExecPin = SetFieldsInStruct->FindPinChecked(UEdGraphSchema_K2::PN_Then, EEdGraphPinDirection::EGPD_Output);
    const TSharedPtr<FKismetCompiledStatement> NextStatement = PeekNextValidStatement();
    
    this->ExecPinPatchUpMap.Add(OutputExecPin, NextStatement);

    return SetFieldsInStruct;
}

UEdGraphNode* FKismetGraphDecompiler::CreateStructMemberSetNode(TSharedPtr<FKismetTerminal> StructTerminal) {
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();
    if (!IsUserCreatedLocalVariable(StructTerminal) || StructTerminal->ContextType != FKismetTerminal::EContextType_Struct) return NULL;

    const FString LocalVariableName = StructTerminal->AssociatedVarProperty;
    UScriptStruct* StructTypeByTerminal = Cast<UScriptStruct>(StructTerminal->Type.PinSubCategoryObject);

    FBPVariableDescription* LocalVariable = FBlueprintEditorUtils::FindLocalVariable(OwnerBlueprint, EditorGraph, *LocalVariableName);
    //The reconstructed graph may lack this compiler-temp local (name/GUID drift, or a struct member-set whose backing
    //local we did not create) → degrade instead of crashing the whole F3 sweep.
    if (!LocalVariable) return EmitFailureComment(FString::Printf(TEXT("struct-member-set local '%s' missing (deferred)"), *LocalVariableName));

    UScriptStruct* StructTypeByLocalVariable = Cast<UScriptStruct>(LocalVariable->VarType.PinSubCategoryObject);
    if (!StructTypeByTerminal || StructTypeByTerminal != StructTypeByLocalVariable) return NULL;
    
    //Allocate node and connect pins that have statements associated with them
    UK2Node_StructMemberSet* MemberSetK2Node = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_StructMemberSet>(EditorGraph, NodePosition, EK2NewNodeFlags::None,
        [&](UK2Node_StructMemberSet* MemberSetNode){
        MemberSetNode->StructType = StructTypeByLocalVariable;
        MemberSetNode->VariableReference.SetLocalMember(LocalVariable->VarName, Function, LocalVariable->VarGuid);
    });

    //Record first statement related to struct member set - it will be jumped to from previous node
    const TSharedPtr<FKismetCompiledStatement> FirstStatement = PeekStatement();

    //Connect input pins with terminals associated with them
    //It will work because technically MakeStruct is a child of StructMemberSet node
    ConnectMakeStructNodePinsWithTerminals(MemberSetK2Node, StructTerminal);
    
    //Since this is an impure node, we need to record input and output pins
    UEdGraphPin* InputExecPin = MemberSetK2Node->FindPinChecked(UEdGraphSchema_K2::PN_Execute, EEdGraphPinDirection::EGPD_Input);
    this->NodeExecPinInputMap.Add(FirstStatement, InputExecPin);

    //This node does not perform any jumps on it's own, so it will just execute next statement in the instruction list
    UEdGraphPin* OutputExecPin = MemberSetK2Node->FindPinChecked(UEdGraphSchema_K2::PN_Then, EEdGraphPinDirection::EGPD_Output);
    const TSharedPtr<FKismetCompiledStatement> NextStatement = PeekNextValidStatement();
    this->ExecPinPatchUpMap.Add(OutputExecPin, NextStatement);

    return MemberSetK2Node;
}

UEdGraphNode* FKismetGraphDecompiler::CreateCopyNode() {
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();
    const TSharedPtr<FKismetCompiledStatement> AssignmentStatement = PopStatement();
    //A malformed/degraded assignment (empty RHS or null LHS) must not deref-crash — degrade like CreateVariableSetNode.
    //The Pop above already advanced the cursor, so a null return is progress the driver accepts.
    if (!AssignmentStatement.IsValid() || AssignmentStatement->RHS.Num() == 0 || !AssignmentStatement->LHS.IsValid()) return NULL;
    const TSharedPtr<FKismetTerminal> InputValue = AssignmentStatement->RHS[0];
    const TSharedPtr<FKismetTerminal> LeftHandOperand = AssignmentStatement->LHS;

    //Allocate node and schedule it's pins to be connected later
    UK2Node_Copy* CopyNode = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_Copy>(EditorGraph, NodePosition, EK2NewNodeFlags::None);

    UEdGraphPin* CopyNodeOutputPin = CopyNode->GetCopyResultPin();
    this->IntermediateVariableHandles.Add(LeftHandOperand, CopyNodeOutputPin);

    UEdGraphPin* InputValuePin = CopyNode->GetInputReferencePin();
    this->RecordTerminalRead(InputValuePin, InputValue);

    return CopyNode;
}

UEdGraphNode* FKismetGraphDecompiler::CreateDelegateSetNode() {
    //TODO honestly? I have never seen this node and was unable to create it in editor
    //TODO additionally, I haven't found any references to it in Kismet except in the node itself
    //TODO overall, it seems to be a very complex node that basically allows creation of anonymous Events
    //TODO and binding them to multicast delegates
    //TODO anonymous events apparently would function as normal events/functions bound to multicast delegates
    //TODO through traditional MakeDelegate/AddDelegate node chain.
    //TODO we need to keep an eye on it, but for now this node seems to be unfinished/inaccessible.
    
    return EmitFailureComment(TEXT("UK2Node_DelegateSet unsupported (deferred)"));
}

//TODO K2Node_VariableSet can be prefixed with FlushNetDormancy() function call on the same context object
//TODO if property set is the replicated network property.
//TODO unnecessary FlushNetDormancy() call should be removed during post-processing and sanitization
//TODO because during standard code generation we cannot really know what statement we had coming before us
//TODO we could also try to detect it in CreateFunctionCallNode() and just discard such nodes at the start

//TODO x2 Variable set nodes using BlueprintSetter properties will be compiled to function calls
//TODO x2 These need to be handled in CreateFunctionCallNode() and reflected back into VariableSet nodes

UEdGraphNode* FKismetGraphDecompiler::CreateVariableSetNode() {
    
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();
    const TSharedPtr<FKismetCompiledStatement> AssignmentStatement = PopStatement();
    if (!AssignmentStatement.IsValid() || AssignmentStatement->RHS.Num() == 0 || !AssignmentStatement->LHS.IsValid()) return NULL;
    const TSharedPtr<FKismetTerminal> AssignedTerminal = AssignmentStatement->RHS[0];
    const TSharedPtr<FKismetTerminal> LeftHandOperand = AssignmentStatement->LHS;

    // Compiler-generated LOCAL variable write (ForEach-loop counters, temp arrays like EndStats): reconstruct as a
    // real function-local Set via SetLocalMember. ConfigureVarNode(member scope) would produce a "None" set node.
    if (IsLocalVariable(LeftHandOperand) && !LeftHandOperand->AssociatedVarProperty.IsEmpty())
    {
        const FName LocalName(*LeftHandOperand->AssociatedVarProperty);
        // AddLocalVariable REFUSES any graph that is not GT_Function and returns false without adding — exactly the
        // EVENT-graph path (GT_Ubergraph has no FunctionEntry to hang locals on). Ignoring that false would spawn a Set
        // node referencing a local that does not exist: a silently WRONG graph that still reports clean. This mirrors
        // the guard already present on the READ path (GetOrCreateVariableGetter); it was missing on the WRITE path.
        if (!FBlueprintEditorUtils::FindLocalVariable(OwnerBlueprint, EditorGraph, LocalName)
            && !FBlueprintEditorUtils::AddLocalVariable(OwnerBlueprint, EditorGraph, LocalName, LeftHandOperand->Type, FString()))
        {
            // EVENT GRAPH: locals are impossible (GT_Ubergraph has no FunctionEntry). A real event graph carries a
            // temp as a WIRE, not a variable. If this local is written EXACTLY ONCE across the whole slice (a
            // single-assignment temp — the common compiler shape), convert the write to pure DATAFLOW: alias %L to the
            // assigned value so every read of %L follows PassThroughTerminals straight to the producer (see
            // ResolveTerminalToPin's alias loop). No node, no variable, exec threads through — the correct, state-free
            // reconstruction, and the whole of the "AddLocalVariable refused" degrade family (the #1 event-body PARTIAL
            // cause). A REUSED slot (written >1×, e.g. a loop counter) is NOT single-assignment: a global alias would
            // hand every read the LAST write's value, so those stay degraded (no silent-wrong) — the safe direction.
            int32 LocalWrites = 0;
            for (const TSharedPtr<FKismetCompiledStatement>& St : CompiledStatements)
                if (St.IsValid() && St->LHS.IsValid() && IsLocalVariable(St->LHS)
                    && St->LHS->AssociatedVarProperty == LeftHandOperand->AssociatedVarProperty)
                    ++LocalWrites;
            // Restrict the alias to VALUE-typed single-assignment temps (clean, zero FAILs). Object-typed temps used as
            // a member-access CONTEXT leave setter/call Target pins unwired ("self is not a <Class>; Target must have a
            // connection") — the getter self-pin guard catches variable reads but NOT setter/call contexts, so aliasing
            // objects nets +15 hard FAILs for +1.4% rate. Object + reused temps stay degraded — the structural floor
            // (reused needs dominance-based SSA; naive member-var promotion is prohibitive: AddMemberVariable forces a
            // synchronous skeleton recompile PER temp, dozens per event).
            const FName TCat0 = LeftHandOperand->Type.PinCategory;
            const bool bObjectFamily = (TCat0 == UEdGraphSchema_K2::PC_Object || TCat0 == UEdGraphSchema_K2::PC_Interface
                || TCat0 == UEdGraphSchema_K2::PC_Class || TCat0 == UEdGraphSchema_K2::PC_SoftObject || TCat0 == UEdGraphSchema_K2::PC_SoftClass);
            if (LocalWrites == 1 && !bObjectFamily)
            {
                PassThroughTerminals.Add(FKismetTerminalAsKeyType(LeftHandOperand), AssignedTerminal);
                return NULL;   // dataflow alias; NOT a degrade.
            }
            EmitFailureComment(FString::Printf(
                TEXT("local Set '%s': reused temp (%d writes) in an event graph (no locals) — dataflow alias unsafe; write deferred"),
                *LocalName.ToString(), LocalWrites));
            bDegraded = true;
            return NULL;   // pass-1 driver tolerates a null return (same as the NULL at the top of this function)
        }
        const FGuid Guid = FBlueprintEditorUtils::FindLocalVariableGuidByName(OwnerBlueprint, EditorGraph, LocalName);
        UK2Node_VariableSet* LocalSet = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_VariableSet>(
            EditorGraph, NodePosition, EK2NewNodeFlags::None,
            [&](UK2Node_VariableSet* N) { N->VariableReference.SetLocalMember(LocalName, EditorGraph->GetName(), Guid); });
        if (UEdGraphPin* ExecIn = LocalSet->FindPin(UEdGraphSchema_K2::PN_Execute, EGPD_Input)) this->NodeExecPinInputMap.Add(AssignmentStatement, ExecIn);
        if (UEdGraphPin* ThenPin = LocalSet->FindPin(UEdGraphSchema_K2::PN_Then, EGPD_Output))
        {
            const TSharedPtr<FKismetCompiledStatement> Succ = PeekNextValidStatement();
            if (Succ.IsValid()) this->ExecPinPatchUpMap.Add(ThenPin, Succ);
        }
        if (UEdGraphPin* ValPin = LocalSet->FindPin(LocalName, EGPD_Input)) this->RecordTerminalRead(ValPin, AssignedTerminal);
        return LocalSet;
    }

    //Kismet graph schema knows how to configure variable references automatically
    const UEdGraphSchema_K2* GraphSchema_K2 = CastChecked<UEdGraphSchema_K2>(EditorGraph->GetSchema());
    const FString& AccessedPropertyName = LeftHandOperand->AssociatedVarProperty;
    // Self-member instance vars have a null context (implicit self) → resolve to the owner class, not the Function.
    UStruct* ContextTypeStruct =
        (LeftHandOperand->VarType == FKismetTerminal::EVarType_Instanced && !LeftHandOperand->Context.IsValid() && OwnerBlueprint)
            ? (UStruct*) OwnerBlueprint->SkeletonGeneratedClass
            : ResolveContextTerminalType(LeftHandOperand->Context);

    // Soft-fail (degrade, don't crash) if the property cannot be resolved on the context.
    if (!ContextTypeStruct || !ContextTypeStruct->FindPropertyByName(*AccessedPropertyName)) {
        EmitFailureComment(FString::Printf(TEXT("variable-set target '%s' unresolved (deferred)"), *AccessedPropertyName));
        return NULL;
    }
    
    //Allocate node and try to resolve referenced member at the start
    UK2Node_VariableSet* MemberSetK2Node = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_VariableSet>(EditorGraph, NodePosition, EK2NewNodeFlags::None,
        [&](UK2Node_VariableSet* VariableSet){
            GraphSchema_K2->ConfigureVarNode(VariableSet, *AccessedPropertyName, ContextTypeStruct, OwnerBlueprint);
    });

    //Connect object on which variable is set pin, but only do it if we actually have a context and it is not a local variable
    UEdGraphPin* PossiblySelfPin = MemberSetK2Node->FindPin(UEdGraphSchema_K2::PN_Self, EGPD_Input);
    if (PossiblySelfPin) {
        const TSharedPtr<FKismetTerminal> ContextTerminal = LeftHandOperand->Context;
        if (ContextTerminal.IsValid()) this->RecordTerminalRead(PossiblySelfPin, ContextTerminal);   // self-member: leave default
    }

    //Connect input data type pin. Pass through pin will never be connected since after compilation it will be transformed into separate VariableGet node
    // The Set's value INPUT pin (named after the variable). UK2Node_Variable::GetValuePin() asserts the pin
    // is an OUTPUT (Get-only), which crashes for a Set, so we FindPin the input directly.
    UEdGraphPin* InputValuePin = MemberSetK2Node->FindPin(FName(*AccessedPropertyName), EGPD_Input);
    if (InputValuePin) this->RecordTerminalRead(InputValuePin, AssignedTerminal);

    //Since this node is not pure, we need to connect Exec pins now
    UEdGraphPin* InputExecPin = MemberSetK2Node->FindPinChecked(UEdGraphSchema_K2::PN_Execute, EEdGraphPinDirection::EGPD_Input);
    this->NodeExecPinInputMap.Add(AssignmentStatement, InputExecPin);

    //Connect next node to the execution then pin
    UEdGraphPin* OutputExecPin = MemberSetK2Node->FindPinChecked(UEdGraphSchema_K2::PN_Then, EEdGraphPinDirection::EGPD_Output);

    //REPLICATED-SET IDIOM, trailing half. FKCHandler_VariableSet::Transform auto-generates up to THREE companion
    //statements around ONE Set node, all gated on !HasFieldNotificationBroadcast() (when that is true the net code and
    //broadcast run natively and NONE are emitted). Final exec order the engine builds:
    //
    //    [FlushNetDormancy] -> Set -> [MarkPropertyDirtyFromRepIndex] -> [RepNotify]
    //
    //(MarkPropertyDirty is spliced in AFTER the RepNotify link is made, so it lands BETWEEN the Set and the RepNotify.)
    //The reconstructed node RE-EMITS every one of them, so each must be consumed here or it is emitted TWICE. The
    //leading FlushNetDormancy is consumed by the pass-1 lookahead (it precedes this statement); the two trailing ones
    //are consumed below, IN THE ENGINE'S ORDER.
    //
    //This previously peeked for the RepNotify at offset 0 and so MISSED it on any push-model net property: the
    //statement sitting immediately after the Let is MarkPropertyDirtyFromRepIndex, not the RepNotify. Each companion is
    //PEEKed and only consumed on an exact match — on real bytecode it may be reordered/inlined/absent. Never crash.
    if (!MemberSetK2Node->HasFieldNotificationBroadcast()) {
        //MarkPropertyDirtyFromRepIndex (UNetPushModelHelpers) — emitted for EVERY net property, and generated even when
        //push model is compiled out (FKCPushModelHelpers::ConstructMarkDirtyNodeForProperty), so it is always present.
        if (MemberSetK2Node->IsNetProperty()) {
            const TSharedPtr<FKismetCompiledStatement> MarkDirtyStatement = PeekStatement();
            if (MarkDirtyStatement.IsValid() && MarkDirtyStatement->Type == ECompiledStatementType::KCST_CallFunction
                && MarkDirtyStatement->FunctionToCall
                && MarkDirtyStatement->FunctionToCall->GetFName() == TEXT("MarkPropertyDirtyFromRepIndex")) {
#if MIF_KR_DEBUG
                UE_LOG(LogMifKismetReconstructor, Warning,
                    TEXT("[rep-set] consumed MarkPropertyDirtyFromRepIndex after Set '%s' (the Set node re-emits it)"),
                    *AccessedPropertyName);
#endif
                PopStatement();
            }
        }

        //Local RepNotify (blueprint-defined OnRep_*) — now reached correctly, MarkPropertyDirty having been consumed.
        if (MemberSetK2Node->HasLocalRepNotify()) {
            const TSharedPtr<FKismetCompiledStatement> RepNotifyStatement = PeekStatement();
            if (RepNotifyStatement.IsValid() && RepNotifyStatement->Type == ECompiledStatementType::KCST_CallFunction
                && RepNotifyStatement->FunctionToCall && RepNotifyStatement->FunctionToCall->GetFName() == MemberSetK2Node->GetRepNotifyName()) {
#if MIF_KR_DEBUG
                UE_LOG(LogMifKismetReconstructor, Warning,
                    TEXT("[rep-set] consumed RepNotify '%s' after Set '%s' (the Set node re-emits it)"),
                    *MemberSetK2Node->GetRepNotifyName().ToString(), *AccessedPropertyName);
#endif
                PopStatement();
            }
        }
    }

    //Connect next statement
    const TSharedPtr<FKismetCompiledStatement> NextStatement = PeekNextValidStatement();
    this->ExecPinPatchUpMap.Add(OutputExecPin, NextStatement);

    return MemberSetK2Node;
}

UEdGraphNode* FKismetGraphDecompiler::CreateVariableSetByRefNode() {
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();
    const TSharedPtr<FKismetCompiledStatement> AssignmentStatement = PopStatement();
    //Degrade a malformed/degraded assignment instead of deref-crashing (Pop already advanced → null return is progress).
    if (!AssignmentStatement.IsValid() || AssignmentStatement->RHS.Num() == 0 || !AssignmentStatement->LHS.IsValid()) return NULL;
    const TSharedPtr<FKismetTerminal> AssignedTerminal = AssignmentStatement->RHS[0];
    const TSharedPtr<FKismetTerminal> LeftHandOperand = AssignmentStatement->LHS;

    //Allocate node without any predefined settings since it doesn't need any
    UK2Node_VariableSetRef* SetVariableByRef = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_VariableSetRef>(EditorGraph, NodePosition, EK2NewNodeFlags::None);

    //Connect input value pins first
    UEdGraphPin* TargetPin = SetVariableByRef->GetTargetPin();
    UEdGraphPin* AssignedValuePin = SetVariableByRef->GetValuePin();
    
    this->RecordTerminalRead(TargetPin, LeftHandOperand);
    this->RecordTerminalRead(AssignedValuePin, AssignedTerminal);

    //Since this node is not pure, we need to connect Exec pins now
    UEdGraphPin* InputExecPin = SetVariableByRef->FindPinChecked(UEdGraphSchema_K2::PN_Execute, EEdGraphPinDirection::EGPD_Input);
    this->NodeExecPinInputMap.Add(AssignmentStatement, InputExecPin);

    //This node does not perform any jumps on it's own, so it will just execute next statement in the instruction list
    UEdGraphPin* OutputExecPin = SetVariableByRef->FindPinChecked(UEdGraphSchema_K2::PN_Then, EEdGraphPinDirection::EGPD_Output);
    const TSharedPtr<FKismetCompiledStatement> NextStatement = PeekNextValidStatement();
    this->ExecPinPatchUpMap.Add(OutputExecPin, NextStatement);
    
    return SetVariableByRef;
}

UEdGraphNode* FKismetGraphDecompiler::CreateMakeDelegateNode() {
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();
    const TSharedPtr<FKismetCompiledStatement> AssignmentStatement = PopStatement();
    //Every assumption below was reconstructed from cooked bytecode — degrade instead of asserting. The Pop already
    //advanced the cursor, so a null return is progress the driver accepts. Needs RHS[0] (fn name) + RHS[1] (self).
    if (!AssignmentStatement.IsValid() || AssignmentStatement->RHS.Num() < 2) return NULL;
    const TSharedPtr<FKismetTerminal> AssignedDelegate = AssignmentStatement->LHS;
    if (!AssignedDelegate.IsValid() || !IsLocalVariable(AssignedDelegate)
        || !AssignedDelegate->AssociatedVarProperty.StartsWith(TEXT("K2Node_CreateDelegate_OutputDelegate"))) {
        EmitFailureComment(TEXT("MakeDelegate LHS not the expected CreateDelegate temp (deferred)"));
        return NULL;
    }

    UK2Node_CreateDelegate* CreateDelegateNode = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_CreateDelegate>(EditorGraph, NodePosition, EK2NewNodeFlags::None);

    //We cannot set delegate function now because scope of the delegate is unknown since
    //connections from terminals are not handled yet
    //To work around it, we record node and function name we need to set on it in patch up map
    const TSharedPtr<FKismetTerminal> FunctionNameTerminal = AssignmentStatement->RHS[0];
    if (!FunctionNameTerminal.IsValid() || !FunctionNameTerminal->bIsLiteral) {
        EmitFailureComment(TEXT("MakeDelegate function-name arg is not a literal (deferred)"));
        return NULL;
    }

    const FString FunctionName = FunctionNameTerminal->StringLiteral;
    this->CreateDelegatePatchUpMap.Add(CreateDelegateNode, *FunctionName);

    //Connect self pin
    const TSharedPtr<FKismetTerminal> ObjectInputTerminal = AssignmentStatement->RHS[1];
    UEdGraphPin* SelfContextPin = CreateDelegateNode->GetObjectInPin();
    this->RecordTerminalRead(SelfContextPin, ObjectInputTerminal);

    //Record delegate output pin as associated to this node
    UEdGraphPin* DelegateOutputPin = CreateDelegateNode->GetDelegateOutPin();
    this->IntermediateVariableHandles.Add(AssignedDelegate, DelegateOutputPin);
    
    return CreateDelegateNode;
}

UEdGraphNode* FKismetGraphDecompiler::CreateMulticastDelegateNode(TSubclassOf<UK2Node_BaseMCDelegate> NodeClass) {
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();
    const UEdGraphSchema_K2* GraphSchema_K2 = CastChecked<UEdGraphSchema_K2>(EditorGraph->GetSchema());
    const TSharedPtr<FKismetCompiledStatement> DelegateStatement = PopStatement();

    //Resolve context class type. Blueprints cannot have event dispatchers as local variables, so we should be alright
    if (!DelegateStatement.IsValid() || !DelegateStatement->LHS.IsValid()) return NULL;   // degraded/absent delegate statement
    const TSharedPtr<FKismetTerminal> LeftSideTerminal = DelegateStatement->LHS;
    const TSharedPtr<FKismetTerminal> SelfContextTerminal = LeftSideTerminal->Context;
    // ResolveContextTerminalType can now degrade to NULL (unresolved/mismatched context) or a non-UClass UStruct —
    // Cast + guard instead of CastChecked so a bad delegate context degrades this node, not the whole editor.
    UClass* ContextTerminalClassType = Cast<UClass>(ResolveContextTerminalType(SelfContextTerminal));
    if (!ContextTerminalClassType) {
        EmitFailureComment(TEXT("multicast-delegate context class unresolved (deferred)"));
        return NULL;
    }

    //ResolveContextTerminalType returns SkeletonGeneratedClass for EX_Self ONLY. A variable typed to the SOURCE class now
    //resolves to that COOKED class, not the skeleton (the transformer's GetTypeSelfScope round-trips pin types back to the
    //class the "<SELF>" token was written against) — so for the F3/batch copy, which is a SIBLING of the cooked class, this
    //is legitimately false for a source-class-typed delegate context.
    const bool bIsSelfContext = OwnerBlueprint->SkeletonGeneratedClass->IsChildOf(ContextTerminalClassType);

    //Resolve delegate property. Multicast delegate related nodes will only work with UMulticastDelegateProperties.
    //PropertyName is reconstructed → the lookup can miss or resolve to a non-MC-delegate property; CastFieldChecked
    //would assert on either. CastField + guard degrades the node instead of crashing the sweep.
    const FString PropertyName = LeftSideTerminal->AssociatedVarProperty;
    FMulticastDelegateProperty* DelegateProperty = CastField<FMulticastDelegateProperty>(ContextTerminalClassType->FindPropertyByName(*PropertyName));
    if (!DelegateProperty) {
        EmitFailureComment(FString::Printf(TEXT("multicast-delegate property '%s' unresolved or not a multicast delegate (deferred)"), *PropertyName));
        return NULL;
    }
    
    //Allocate node of the class passed as the argument
    UK2Node_BaseMCDelegate* DelegateNode = Cast<UK2Node_BaseMCDelegate>(
        FEdGraphSchemaAction_K2NewNode::CreateNode(EditorGraph, TArrayView<UEdGraphPin*>(), NodePosition,
            [NodeClass](UEdGraph* InParentGraph){
                return NewObject<UK2Node>(InParentGraph, NodeClass);
            },
            [DelegateProperty, bIsSelfContext, ContextTerminalClassType](UK2Node* NewNode){
                UK2Node_BaseMCDelegate* DelegateNode = CastChecked<UK2Node_BaseMCDelegate>(NewNode);
                DelegateNode->SetFromProperty(DelegateProperty, bIsSelfContext, ContextTerminalClassType);
            },
            EK2NewNodeFlags::None));

    //CreateNode(NodeClass) can hand back something the Cast rejects → guard before every deref below (FindSelfPin etc.).
    if (!DelegateNode) {
        EmitFailureComment(TEXT("multicast-delegate node spawn failed (deferred)"));
        return NULL;
    }

    //Interesting thing: K2Node_BaseMCDelegate can accept MULTIPLE Self inputs and perform operation on each of them
    //We don't really need to have special handling, because what it does is basically generating
    //a statement for each input, or prefixing it with array iteration if input is an array.
    //Either way, functionally it's completely the same thing as having multiple delegate nodes, which we are doing.

    //Connect Self pin first (only if present — a malformed node may lack it; skip rather than assert).
    UEdGraphPin* SelfPin = GraphSchema_K2->FindSelfPin(*DelegateNode, EGPD_Input);
    if (SelfPin) this->RecordTerminalRead(SelfPin, SelfContextTerminal);

    //Connect delegate input pin if the target node has one (ClearDelegate does not, for example)
    //If we don't have the delegate pin, RHS operand list will be empty too
    UEdGraphPin* DelegatePin = DelegateNode->GetDelegatePin();

    if (DelegatePin != NULL && DelegateStatement->RHS.Num() > 0) {
        //RHS was assumed non-empty here; a degraded delegate statement can have none → guard instead of asserting.
        const TSharedPtr<FKismetTerminal> RightHandOperand = DelegateStatement->RHS[0];
        this->RecordTerminalRead(DelegatePin, RightHandOperand);
    }

    //Connect Exec input and output pins, since neither of these nodes are pure
    UEdGraphPin* InputExecPin = DelegateNode->FindPinChecked(UEdGraphSchema_K2::PN_Execute, EEdGraphPinDirection::EGPD_Input);
    this->NodeExecPinInputMap.Add(DelegateStatement, InputExecPin);

    //This node does not perform any jumps on it's own, so it will just execute next statement in the instruction list
    UEdGraphPin* OutputExecPin = DelegateNode->FindPinChecked(UEdGraphSchema_K2::PN_Then, EEdGraphPinDirection::EGPD_Output);
    const TSharedPtr<FKismetCompiledStatement> NextStatement = PeekNextValidStatement();
    this->ExecPinPatchUpMap.Add(OutputExecPin, NextStatement);

    return DelegateNode;
}

UEdGraphNode* FKismetGraphDecompiler::CreateFunctionCallNode() {
    const FVector2D NodePosition = EditorGraph->GetGoodPlaceForNewNode();
    const TSharedPtr<FKismetCompiledStatement> Stmt = PopStatement();   // advances the cursor
    if (!Stmt.IsValid() || Stmt->Type != ECompiledStatementType::KCST_CallFunction) return NULL;

    UFunction* Func = Stmt->FunctionToCall;
    if (!Func) return NULL;
    if (Stmt->bIsCallIntoUbergraph) return NULL;   // event bridge — no visible node (deferred)

    // SetFromFunction (below) → FMemberReference::SetGivenSelfScope unconditionally derefs the call target's
    // owner class (InMemberParentClass->ClassGeneratedBy, MemberReference.cpp:87) with no null-guard → editor-killing
    // AV reading 0x120. Degrade this call unless the owner is a live, current class: IsValid() rejects null +
    // pending-kill; CLASS_NewerVersionExists rejects a stale/reinstanced class swapped out from under a raw
    // UFunction* mid-sweep. (Hit by BP_BaseNPC; StatsManager never did.)
    UClass* FuncOwner = Func->GetOwnerClass();
    // A self-call to a sibling function resolves against the new BP's SkeletonGeneratedClass, which regenerates
    // (reinstances) as more function graphs are added across the F3 sweep → the earlier-resolved UFunction* goes stale
    // (owner flagged CLASS_NewerVersionExists, its object name gains a _N suffix). Re-resolve by the ORIGINAL name
    // (carried in the IR) on the LIVE skeleton so the sibling call reconstructs instead of dropping.
    if ((!IsValid(FuncOwner) || FuncOwner->HasAnyClassFlags(CLASS_NewerVersionExists))
        && Stmt->FunctionName != NAME_None && OwnerBlueprint && OwnerBlueprint->SkeletonGeneratedClass) {
        if (UFunction* LiveFunc = OwnerBlueprint->SkeletonGeneratedClass->FindFunctionByName(Stmt->FunctionName)) {
            Func = LiveFunc;
            FuncOwner = Func->GetOwnerClass();
        }
    }
    if (!IsValid(FuncOwner) || FuncOwner->HasAnyClassFlags(CLASS_NewerVersionExists)) {
        EmitFailureComment(FString::Printf(TEXT("call target owner class missing/stale/reinstanced: %s"), *Func->GetName()));
        return NULL;
    }

    const bool bStatic = Func->HasAnyFunctionFlags(FUNC_Static);

    // Spawn the call node; SetFromFunction ONLY (keeps the member GUID and picks self-vs-external).
    // Array-library functions (Array_Add/Get/Length/…, tagged meta=(ArrayParm=...)) MUST be a UK2Node_CallArrayFunction:
    // that node class propagates the wildcard TargetArray/Item container type FROM its connection. A plain
    // UK2Node_CallFunction has no container-wildcard logic, so its TargetArray would stay "undetermined" forever.
    // A PARENT call (`base.Foo()`) must be a UK2Node_CallParentFunction, not a plain call. KismetCompilerVMBackend.cpp:1312
    // emits the FINAL opcode when `FunctionToCall->HasAnyFunctionFlags(FUNC_Final) || Statement.bIsParentContext`, so a
    // FinalFunction whose target is NOT final can only have been a parent call — that is the exact inversion the
    // transformer already records in bIsParentContext (nothing here re-derives it). It matters because the call is
    // resolved off the SKELETON, which finds the CHILD's override: a plain UK2Node_CallFunction would therefore emit a
    // call to the function we are currently reconstructing (self-recursion), not to the super.
    // Resolve the PARENT's function explicitly — UK2Node_CallParentFunction::SetFromFunction does
    // FunctionReference.SetDirect(..., Function->GetOwnerClass(), bIsConsideredSelfContext=false), so handing it the
    // child's override would stamp the wrong owner class.
    UFunction* ParentFunc = (Stmt->bIsParentContext && !bStatic && OwnerBlueprint && OwnerBlueprint->ParentClass)
        ? OwnerBlueprint->ParentClass->FindFunctionByName(Func->GetFName())
        : nullptr;

    const bool bIsArrayFunc = Func->HasMetaData(TEXT("ArrayParm"));
    UK2Node_CallFunction* Node =
        // Degrade softly: only take the parent path when the parent genuinely HAS the function. If the flag ever fires
        // where no such parent function exists, fall through to the existing plain-call path rather than spawning a
        // CallParent node with a dangling reference (which would break an otherwise-reconstructable function).
        ParentFunc
        ? (UK2Node_CallFunction*) FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_CallParentFunction>(
            EditorGraph, NodePosition, EK2NewNodeFlags::None,
            [ParentFunc](UK2Node_CallParentFunction* N){ N->SetFromFunction(ParentFunc); })
        : bIsArrayFunc
        ? (UK2Node_CallFunction*) FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_CallArrayFunction>(
            EditorGraph, NodePosition, EK2NewNodeFlags::None,
            [Func](UK2Node_CallArrayFunction* N){ N->SetFromFunction(Func); })
        : FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_CallFunction>(
            EditorGraph, NodePosition, EK2NewNodeFlags::None,
            [Func](UK2Node_CallFunction* N){ N->SetFromFunction(Func); });
    if (!Node) return NULL;

    const bool bPure = Node->IsNodePure();

    // Exec pins (impure only): register this statement's exec-in + its Then -> the next statement.
    if (!bPure) {
        if (UEdGraphPin* ExecIn = Node->FindPin(UEdGraphSchema_K2::PN_Execute, EGPD_Input)) {
            this->NodeExecPinInputMap.Add(Stmt, ExecIn);
        }
        if (UEdGraphPin* ThenPin = Node->FindPin(UEdGraphSchema_K2::PN_Then, EGPD_Output)) {
            const TSharedPtr<FKismetCompiledStatement> Successor = PeekNextValidStatement(0);
            if (Successor.IsValid()) this->ExecPinPatchUpMap.Add(ThenPin, Successor);
        }
    }

    // Self / target pin (non-static calls with a real, non-self context only).
    if (!bStatic && Stmt->FunctionContext.IsValid() && !IsSelfTerminal(Stmt->FunctionContext)) {
        if (UEdGraphPin* SelfPin = Node->FindPin(UEdGraphSchema_K2::PN_Self, EGPD_Input)) {
            this->RecordTerminalRead(SelfPin, Stmt->FunctionContext);
        }
    }

    // Arguments: mirror the transformer's CPF_Parm walk (skip the return param — no RHS slot consumed).
    int32 ArgIdx = 0;
    for (TFieldIterator<FProperty> PropIt(Func); PropIt && (PropIt->PropertyFlags & CPF_Parm); ++PropIt) {
        FProperty* Param = *PropIt;
        if (Param->HasAnyPropertyFlags(CPF_ReturnParm)) continue;
        const TSharedPtr<FKismetTerminal> Arg = Stmt->RHS.IsValidIndex(ArgIdx) ? Stmt->RHS[ArgIdx] : nullptr;
        ++ArgIdx;
        if (!Arg.IsValid()) continue;
        const bool bOut = Param->HasAnyPropertyFlags(CPF_OutParm);
        const bool bByRef = Param->HasAnyPropertyFlags(CPF_ReferenceParm);
        if (!bOut || bByRef) {
            if (UEdGraphPin* InPin = Node->FindPin(Param->GetFName(), EGPD_Input)) {
                this->RecordTerminalRead(InPin, Arg);            // input / in-out
            }
        } else {
            if (UEdGraphPin* OutPin = Node->FindPin(Param->GetFName(), EGPD_Output)) {
                this->IntermediateVariableHandles.Add(FKismetTerminalAsKeyType(Arg), OutPin);   // write-only out
            }
        }
    }
    if (ArgIdx != Stmt->RHS.Num()) {
        EmitFailureComment(FString::Printf(TEXT("call arg drift on %s: walked %d, RHS %d"), *Func->GetName(), ArgIdx, Stmt->RHS.Num()));
    }

    // Return value -> ReturnValue output pin, keyed by the LHS terminal for later reads.
    if (UEdGraphPin* RetPin = Node->FindPin(UEdGraphSchema_K2::PN_ReturnValue, EGPD_Output)) {
        if (Stmt->LHS.IsValid()) {
            this->IntermediateVariableHandles.Add(FKismetTerminalAsKeyType(Stmt->LHS), RetPin);
        }
    }
    return Node;
}

// Standalone object/interface → bool (KCST_ObjectToBool not paired with a DynamicCast) reconstructed as a pure
// UKismetSystemLibrary::IsValid call — yields a real bool output pin (the K2 schema has no object→bool autocast, so
// a forced object→bool link would not compile). Returns the bool ReturnValue pin (nullptr on failure).
UEdGraphPin* FKismetGraphDecompiler::EmitObjectIsValidNode(TSharedPtr<FKismetTerminal> SourceObject) {
    UFunction* IsValidFunc = UKismetSystemLibrary::StaticClass()->FindFunctionByName(TEXT("IsValid"));
    if (!IsValidFunc) return nullptr;
    UK2Node_CallFunction* Node = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_CallFunction>(
        EditorGraph, FVector2D(NextNodePosX, 160.0), EK2NewNodeFlags::None,
        [IsValidFunc](UK2Node_CallFunction* N){ N->SetFromFunction(IsValidFunc); });
    if (!Node) return nullptr;
    ++NodesCreated; Node->NodePosX = NextNodePosX; NextNodePosX += 220;   // pure node: self-bump position
    if (UEdGraphPin* ObjectPin = Node->FindPin(TEXT("Object"), EGPD_Input))
        this->RecordTerminalRead(ObjectPin, SourceObject);               // object OR interface source (interface->object is a built-in K2 autocast)
    return Node->FindPin(UEdGraphSchema_K2::PN_ReturnValue, EGPD_Output);
}

// Resolve the concrete UDataTable a member-variable DataTable read refers to, from the owning class CDO default.
// (A cooked source class's CDO holds the serialized member default — the common DDS2 "const config table" case.)
UDataTable* FKismetGraphDecompiler::ResolveMemberDataTableDefault(const TSharedPtr<FKismetTerminal>& T) {
    if (!T.IsValid() || T->bIsLiteral || T->AssociatedVarProperty.IsEmpty()) return nullptr;
    if (IsLocalVariable(T)) return nullptr;                 // a function-local temp has no class CDO default
    UClass* SourceClass = nullptr;
    if (!T->Context.IsValid() || IsSelfTerminal(T->Context))
        SourceClass = OwnerBlueprint ? OwnerBlueprint->ParentClass : nullptr;   // cooked source class; its CDO holds the default
    else
        SourceClass = Cast<UClass>(ResolveContextTerminalType(T->Context));     // best-effort context object class
    if (!SourceClass) return nullptr;
    FObjectPropertyBase* ObjProp = CastField<FObjectPropertyBase>(SourceClass->FindPropertyByName(FName(*T->AssociatedVarProperty)));
    if (!ObjProp) return nullptr;
    UObject* CDO = SourceClass->GetDefaultObject(true);
    if (!CDO) return nullptr;
    return Cast<UDataTable>(ObjProp->GetObjectPropertyValue_InContainer(CDO));
}

UScriptStruct* FKismetGraphDecompiler::ResolveOutRowStructFromTerminal(const TSharedPtr<FKismetTerminal>& T) {
    if (!T.IsValid()) return nullptr;
    if (T->Type.PinCategory != UEdGraphSchema_K2::PC_Struct) return nullptr;      // OutRow local must be a struct var
    UScriptStruct* S = Cast<UScriptStruct>(T->Type.PinSubCategoryObject.Get());
    if (!S) return nullptr;
    if (S == FTableRowBase::StaticStruct()) return nullptr;                       // abstract base — not a concrete row
    return S;
}

bool FKismetGraphDecompiler::IsGetDataTableRowCall(const TSharedPtr<FKismetCompiledStatement>& S) const {
    if (!S.IsValid() || S->Type != ECompiledStatementType::KCST_CallFunction) return false;
    UFunction* F = S->FunctionToCall;
    if (!F || F->GetFName() != FName(TEXT("GetDataTableRowFromName"))) return false;
    if (F->GetOwnerClass() != UDataTableFunctionLibrary::StaticClass()) return false;
    return S->RHS.Num() >= 3 && S->LHS.IsValid();   // Table, RowName, OutRow (+ bool return LHS)
}

// GetDataTableRow: the compiler EXPANDS a UK2Node_GetDataTableRow into a CallFunction to the CustomStructureParam
// library fn GetDataTableRowFromName + a Branch on its bool ReturnValue. On a raw CallFunction the OutRow wildcard
// types ONLY from a connection (and re-wildcards when unlinked), so an unwired OutRow errors "type undetermined".
// The specialized node self-resolves OutRow's struct type from the DataTable asset's RowStruct instead.
UEdGraphNode* FKismetGraphDecompiler::CreateGetDataTableRowNode() {
    const FVector2D Pos = EditorGraph->GetGoodPlaceForNewNode();
    const TSharedPtr<FKismetCompiledStatement> Stmt = PopStatement();      // consume the call
    if (!Stmt.IsValid() || Stmt->RHS.Num() < 3) { EmitFailureComment(TEXT("GetDataTableRow malformed (deferred)")); return NULL; }

    UK2Node_GetDataTableRow* Node = FEdGraphSchemaAction_K2NewNode::SpawnNode<UK2Node_GetDataTableRow>(
        EditorGraph, Pos, EK2NewNodeFlags::None, [](UK2Node_GetDataTableRow*){});
    if (!Node) return NULL;

    if (UEdGraphPin* ExecIn = Node->FindPin(UEdGraphSchema_K2::PN_Execute, EGPD_Input))
        this->NodeExecPinInputMap.Add(Stmt, ExecIn);

    // Table (RHS[0]): literal UDataTable → ApplyLiteralToPin sets the pin default (drives the struct-type resolve);
    // linked → real link. Either way via the uniform RecordTerminalRead → Phase-B ResolveTerminalToPin path.
    if (UEdGraphPin* TablePin = Node->GetDataTablePin())   this->RecordTerminalRead(TablePin, Stmt->RHS[0]);
    if (UEdGraphPin* RowNamePin = Node->GetRowNamePin())   this->RecordTerminalRead(RowNamePin, Stmt->RHS[1]);

    // OutRow (RHS[2]) storage terminal → the Result output pin is its producer for downstream struct reads.
    if (UEdGraphPin* ResultPin = Node->GetResultPin())
        if (Stmt->RHS[2].IsValid()) this->IntermediateVariableHandles.Add(FKismetTerminalAsKeyType(Stmt->RHS[2]), ResultPin);

    // If the DataTable comes from a member VARIABLE (not a literal asset), the node can't self-type OutRow. Resolve the
    // row struct — stamped onto OutRow in Phase B.5. PRIMARY: the cooked OutRow arg references a concrete local var whose
    // struct type IS the row struct (authoritative, works even when the table's CDO default is null). FALLBACK: read the
    // member's default UDataTable off the source-class CDO and take its RowStruct.
    if (Stmt->RHS[0].IsValid() && !Stmt->RHS[0]->bIsLiteral)
    {
        UScriptStruct* RowStruct = ResolveOutRowStructFromTerminal(Stmt->RHS[2]);
        if (!RowStruct)
            if (UDataTable* DT = ResolveMemberDataTableDefault(Stmt->RHS[0]))
                RowStruct = DT->RowStruct;
        if (RowStruct) DataTableRowStructByNode.Add(Node, RowStruct);
        else EmitFailureComment(TEXT("GetDataTableRow: OutRow struct unresolved (local var non-struct + member default null) → deferred"));
    }

    // Row Found / Row Not Found exec = the Branch the compiler emitted on the bool ReturnValue. Consume the paired
    // GotoIfNot(cond==our bool LHS): fall-through(cond true)=Row Found; TargetLabel(cond false)=Row Not Found.
    UEdGraphPin* ThenPin = Node->GetThenPin();
    UEdGraphPin* NotFoundPin = Node->GetRowNotFoundPin();
    const TSharedPtr<FKismetCompiledStatement> Branch = PeekStatement(0);
    if (Branch.IsValid() && Branch->Type == ECompiledStatementType::KCST_GotoIfNot
        && Branch->LHS.IsValid() && Stmt->LHS.IsValid() && Branch->LHS->operator==(*Stmt->LHS)) {
        PopStatement();                                                     // consume the branch
        if (ThenPin) { const TSharedPtr<FKismetCompiledStatement> RF = PeekNextValidStatement(0);
                       if (RF.IsValid()) this->ExecPinPatchUpMap.Add(ThenPin, RF); }
        if (NotFoundPin && Branch->TargetLabel.IsValid()) this->ExecPinPatchUpMap.Add(NotFoundPin, Branch->TargetLabel);
    } else if (ThenPin) {                                                   // no paired branch → best-effort thread onward
        const TSharedPtr<FKismetCompiledStatement> Succ = PeekNextValidStatement(0);
        if (Succ.IsValid()) this->ExecPinPatchUpMap.Add(ThenPin, Succ);
    }
    return Node;
}

UEdGraphNode* FKismetGraphDecompiler::GenerateNodeForStatement() {
    const TSharedPtr<FKismetCompiledStatement> Statement = PeekStatement();

    //Just skip Nop instructions altogether and skip to processing next one
    if (Statement->Type == ECompiledStatementType::KCST_Nop) {
        PopStatement();
        return NULL;
    }

    //KCST_CreateMap statement can be generated only in two cases: either by user-created K2Node_MakeMap,
    //or by compiler generated K2Node_MakeVariable, generated to create a map value to be then used by K2Node_VariableSet
    //apparently both nodes have roughly identical functionality, but K2Node_VariableSet is capable of
    //"automatically initializing" itself from property types, but it's not really important during decompilation,
    //so we basically just treat every KCST_CreateMap opcode as K2Node_MakeMap
    //Later, if it can be reduced into default local variable value assignment, it will be removed and set as default value,
    //which will cause the generation of K2Node_MakeVariable by function entry again, resulting in the equal graph
    if (Statement->Type == ECompiledStatementType::KCST_CreateMap) {
        return CreateMakeMapNode();
    }

    //Exactly the same thing for KCST_CreateSet instruction - we treat all of them as K2Node_MakeSet
    if (Statement->Type == ECompiledStatementType::KCST_CreateSet) {
        return CreateMakeSetNode();
    }

    //Exactly the same thing with KCST_CreateArray instruction - we treat all of them as K2Node_MakeArray
    if (Statement->Type == ECompiledStatementType::KCST_CreateArray) {
        return CreateMakeArrayNode();
    }

    //These two instructions are only ever emitted to K2Node_DynamicCast, so it is completely safe to convert them directly
    if (Statement->Type == ECompiledStatementType::KCST_DynamicCast ||
        Statement->Type == ECompiledStatementType::KCST_CrossInterfaceCast) {
        return CreateCastNode(false);
    }

    //KCST_MetaCast will be emitted only by cast nodes casting from one class type to another
    if (Statement->Type == ECompiledStatementType::KCST_MetaCast) {
        return CreateCastNode(true);
    }

    //These statements can appear in multiple cases:
    //1) As the part of K2Node_DynamicCast
    //2) Instead of KCST_Assignment when trying to assign interface value to object property or vice versa
    //3) When interface is passed to a function call node where object argument is expected, or vise versa
    if (Statement->Type == ECompiledStatementType::KCST_CastInterfaceToObj ||
        Statement->Type == ECompiledStatementType::KCST_CastObjToInterface) {
        
        //User-defined variables can only happen as the part of KCST_Assignment instructions
        if (IsUserCreatedLocalVariable(Statement->LHS)) {
            return CreateAssignmentNode();
        }
        
        //Otherwise it is a generated variable, and we can use a name to differentiate between 3 cases
        const FString VariableName = Statement->LHS->AssociatedVarProperty;

        //Dynamic cast node, handle the same way as KCST_DynamicCast
        if (VariableName.StartsWith(TEXT("K2Node_DynamicCast"))) {
            return CreateCastNode(false);
        }

        //Function call node with parameter converter in-place from interface to object or vice versa
        //Skipping the cast in that case is fine, Kismet Compiler will regenerate it
        //TODO it is really curious case, because usually Editor suggests to generate explicit cast itself
        //TODO but FactoryGame blueprints actually have one such case, so we will support it for now
        if (VariableName.StartsWith(TEXT("CallFunc_")) && VariableName.EndsWith(TEXT("_CastInput"))) {
            //Pop statement of the generated cast
            PopStatement();

            //Mark the output terminal as the pass-through of the input terminal
            const TSharedPtr<FKismetTerminal> InputObjectTerminal = Statement->RHS[1];
            const TSharedPtr<FKismetTerminal> OutputObjectTerminal = Statement->LHS;
            this->PassThroughTerminals.Add(OutputObjectTerminal, InputObjectTerminal);
            return NULL;
        }
        
        //Otherwise it should be assignment node with generated variable name, which can happen for various node types
        return CreateAssignmentNode();
    }

    //Assignment statements can be a part of multiple nodes, exact handling will be decided in CreateAssignmentNode
    if (Statement->Type == ECompiledStatementType::KCST_Assignment) {
        return CreateAssignmentNode();
    }

    //These statements are only generated by delegate handling nodes
    if (Statement->Type == ECompiledStatementType::KCST_BindDelegate) {
        return CreateMakeDelegateNode();
    }
    
    //Next 3 statements are basically handled in the same way, only thing different is the class of node generated
    if (Statement->Type == ECompiledStatementType::KCST_AddMulticastDelegate) {
        return CreateMulticastDelegateNode(UK2Node_AddDelegate::StaticClass());
    }
    if (Statement->Type == ECompiledStatementType::KCST_RemoveMulticastDelegate) {
        return CreateMulticastDelegateNode(UK2Node_RemoveDelegate::StaticClass());
    }
    if (Statement->Type == ECompiledStatementType::KCST_ClearMulticastDelegate) {
        return CreateMulticastDelegateNode(UK2Node_ClearDelegate::StaticClass()); 
    }

    if (Statement->Type == ECompiledStatementType::KCST_CallFunction) {
        if (IsGetDataTableRowCall(Statement)) return CreateGetDataTableRowNode();
        return CreateFunctionCallNode();
    }

    return NULL;
}

UStruct* FKismetGraphDecompiler::ResolveContextTerminalType(TSharedPtr<FKismetTerminal> Terminal) {
    //If context terminal is not valid, it is actually a local variable, and context type is... a function itself
    if (!Terminal.IsValid()) {
        return Function;
    }
    
    //Struct is the type of the terminal, UScriptStruct instance should be stored as sub category object
    if (Terminal->Type.PinCategory == UEdGraphSchema_K2::PC_Struct) {
        return Cast<UScriptStruct>(Terminal->Type.PinSubCategoryObject);   // caller null-checks
    }

    //Type of the terminal is interface, pin sub category object would be object class
    if (Terminal->Type.PinCategory == UEdGraphSchema_K2::PC_Interface) {
        return Cast<UClass>(Terminal->Type.PinSubCategoryObject);   // caller null-checks
    }

    //Type of the terminal is Class, pin sub category is the meta class type
    //Even though type of the context pin is Class, as context Class CDO object will be used
    //so correct context terminal type is the value of meta class as specified in sub object
    if (Terminal->Type.PinCategory == UEdGraphSchema_K2::PC_Class) {
        // A class literal baked as EX_ObjectConst (there is no EX_ClassConst) types as PC_Object yet carries a
        // ClassContext opcode → ContextType/PinCategory can legitimately disagree here. Degrade instead of check()-crashing.
        if (Terminal->ContextType != FKismetTerminal::EContextType_Class) {
            EmitFailureComment(TEXT("class-context terminal ContextType/PinCategory mismatch (deferred)"));
            return NULL;
        }
        
        //Sometimes SubCategory can be Self, then PinSubCategoryObject is ignored
        UClass* MetaClassType;
        if (Terminal->Type.PinSubCategory == UEdGraphSchema_K2::PSC_Self) {
            MetaClassType = OwnerBlueprint->SkeletonGeneratedClass;
        } else {
            MetaClassType = Cast<UClass>(Terminal->Type.PinSubCategoryObject);
        }
        
        return MetaClassType;
    }

    //Objects are handled exactly in the same way as PC_Class
    if (Terminal->Type.PinCategory == UEdGraphSchema_K2::PC_Object) {
        if (Terminal->ContextType != FKismetTerminal::EContextType_Object) {
            EmitFailureComment(TEXT("object-context terminal ContextType/PinCategory mismatch (deferred)"));
            return NULL;
        }
        
        //Sometimes SubCategory can be Self, then PinSubCategoryObject is ignored
        UClass* ObjectClassType;
        if (Terminal->Type.PinSubCategory == UEdGraphSchema_K2::PSC_Self) {
            ObjectClassType = OwnerBlueprint->SkeletonGeneratedClass;
        } else {
            ObjectClassType = Cast<UClass>(Terminal->Type.PinSubCategoryObject);
        }
        
        return ObjectClassType;
    }

    EmitFailureComment(FString::Printf(TEXT("unknown context terminal type %s/%s (deferred)"), *Terminal->Type.PinCategory.ToString(), *Terminal->Type.PinSubCategory.ToString()));
    return NULL;
}
