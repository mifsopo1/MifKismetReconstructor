#include "AssetGeneration/KismetBytecodeTransformer.h"
#include "BPTerminal.h"
#include "EdGraphSchema_K2.h"
#include "Engine/Blueprint.h"
#include "Engine/LatentActionManager.h"
#include "Toolkit/PropertyTypeHelper.h"

FKismetBytecodeTransformer::FKismetBytecodeTransformer(UBlueprint* Blueprint, UClass* InSourceClass) {
    this->OwnerBlueprint = Blueprint;
    this->SourceClass = InSourceClass;
    this->ExecuteUbergraphFunctionName = UEdGraphSchema_K2::FN_ExecuteUbergraphBase.ToString() + TEXT("_") + Blueprint->GetName();
}

// The disassembler stamps "<SELF>" into a serialized pin type for every object ref equal to ITS SelfScope — the COOKED
// source class (KismetBytecodeDisassemblerJson.cpp:950, `Function->GetTypedOuter<UClass>()`; SerializeObjectRef =
// `Object == SelfScope ? "<SELF>" : GetPathName()`). Deserializing that token against the COPY's skeleton silently
// rewrites SourceClass->NewClass in the TYPE layer — while the copy's member variables (CopyVariables ->
// ConvertPropertyToPinType) and function-entry param pins (AddFunctionGraph<UFunction> from the cooked signature) stay
// typed to the COOKED class. Two class namespaces then collide inside one graph, which is exactly the
// "<Copy>_C is not compatible with X" / "Self Object Reference is not compatible with X" failures. So round-trip TYPES
// back to the class they were written against. (Genuine EX_Self / self-context still resolve to the copy's skeleton.)
UClass* FKismetBytecodeTransformer::GetTypeSelfScope() const {
    if (SourceClass) { return SourceClass; }
    // Legacy fallback = pre-fix behaviour. Separate returns + explicit cast: SkeletonGeneratedClass is a
    // TSubclassOf<UObject>, so a ternary against a UClass* would be an ambiguous conditional (both implicitly convert).
    return OwnerBlueprint ? (UClass*) OwnerBlueprint->SkeletonGeneratedClass : nullptr;
}

void FKismetBytecodeTransformer::SetUberGraphTransformer(TSharedPtr<FKismetBytecodeTransformer> Transformer) {
    //This was a fatal on a predicate that is WRONG for the copy path: IsUberGraphFunction() matches the transformed
    //function name against "ExecuteUbergraph_" + OwnerBlueprint->GetName(), i.e. the COPY's name ("MifKrBatch_BP_Foo"),
    //never the cooked source's — so a legitimate ubergraph transformer fires it (which is exactly why the event path
    //refuses to call this at all; see MifReconstructEvent.cpp). Warn and accept: the caller knows what it passed, and
    //a mis-set transformer degrades a call-into-ubergraph, it does not justify killing the editor.
    if (!Transformer.IsValid()) {
        UE_LOG(LogTemp, Warning, TEXT("[MifKR] SetUberGraphTransformer called with an invalid transformer (ignored)"));
        return;
    }
    if (!Transformer->IsUberGraphFunction()) {
        UE_LOG(LogTemp, Warning, TEXT("[MifKR] SetUberGraphTransformer: '%s' does not name-match this blueprint's ubergraph (accepted anyway)"),
            *Transformer->CurrentFunctionName);
    }
    this->UberGraphTransformer = Transformer;
}

void FKismetBytecodeTransformer::SetSourceStatements(const FString& FunctionName, const TArray<TSharedPtr<FJsonObject>>& Statements) {
    this->CurrentFunctionName = FunctionName;
    this->ResultStatements.Reserve(Statements.Num());
    
    for (const TSharedPtr<FJsonObject> StatementObject : Statements) {
        const uint32 StatementIndex = StatementObject->GetIntegerField(TEXT("StatementIndex"));
        TSharedPtr<FKismetCompiledStatement> Statement = ProcessStatement(StatementObject);

        this->StatementsByOffset.Add(StatementIndex, Statement);
        this->ResultStatements.Add(Statement);
    }
}

TArray<TSharedPtr<FKismetCompiledStatement>> FKismetBytecodeTransformer::FinishGeneration() {
    //Apply patch-ups to jump statements
    for (const TPair<TSharedPtr<FKismetCompiledStatement>, int32>& Pair : JumpPatchUpTable) {
        const TSharedPtr<FKismetCompiledStatement> JumpStatement = Pair.Key;
        //Resolve the target offset to the next VALID statement at or after it. Editor-only Tracepoint/WireTracepoint
        //opcodes become NULL entries in StatementsByOffset (ProcessStatement returns null for them), and the cooked
        //compiler routinely aims a jump AT such a tracepoint - it is the debug step-point that fronts the real
        //destination. Taking the null verbatim drops the patch-up and silently severs the branch (e.g. the ELSE arm
        //of every GotoIfNot lands on the tracepoint before its block). Walk forward to the first real statement, the
        //exec destination the tracepoint fronts. StatementIndex is contiguous, so a missing key = past the end.
        TSharedPtr<FKismetCompiledStatement> JumpTarget = nullptr;
        for (int32 Off = Pair.Value; ; ++Off) {
            const TSharedPtr<FKismetCompiledStatement>* P = StatementsByOffset.Find(Off);
            if (!P) break;                        // ran off the end of the statement stream -> leave unresolved
            if (P->IsValid()) { JumpTarget = *P; break; }
        }
        //A jump target may be null if that statement soft-failed (unresolved call). Skip the patch-up — the driver's
        //ResolveExecTarget degrades a dangling jump gracefully — rather than deref a null here.
        if (!JumpStatement.IsValid() || !JumpTarget.IsValid()) {
            continue;
        }
        JumpStatement->TargetLabel = JumpTarget;

        //Replace jump statement type if we are jumping to the return statement
        if (JumpTarget->Type == ECompiledStatementType::KCST_Return) {
            //Replace KCST_UnconditionalGoto with KCST_GotoReturn
            if (JumpStatement->Type == ECompiledStatementType::KCST_UnconditionalGoto) {
                JumpStatement->Type = ECompiledStatementType::KCST_GotoReturn;
            }
            //Replace KCST_GotoIfNot with KCST_GotoReturnIfNot
            if (JumpStatement->Type == ECompiledStatementType::KCST_GotoIfNot) {
                JumpStatement->Type = ECompiledStatementType::KCST_GotoReturnIfNot;
            }
        }
    }

    return ResultStatements;
}

bool FKismetBytecodeTransformer::IsContextInstruction(const FString& InstructionName) {
    return InstructionName == TEXT("Context") ||
        InstructionName == TEXT("Context_FailSilent") ||
        InstructionName == TEXT("ClassContext");
}

bool FKismetBytecodeTransformer::IsCallFunctionInstruction(const FString& InstructionName) {
    return InstructionName == TEXT("CallMath") ||
        InstructionName == TEXT("LocalFinalFunction") ||
        InstructionName == TEXT("FinalFunction") ||
        InstructionName == TEXT("LocalVirtualFunction") ||
        InstructionName == TEXT("VirtualFunction");
}

bool FKismetBytecodeTransformer::IsVariableInstruction(const FString& InstructionName) {
    return InstructionName == TEXT("DefaultVariable") ||
        InstructionName == TEXT("InstanceVariable") ||
        InstructionName == TEXT("LocalVariable") ||
        InstructionName == TEXT("LocalOutVariable");
}

TSharedPtr<FKismetCompiledStatement> FKismetBytecodeTransformer::ProcessStatement(TSharedPtr<FJsonObject> Statement) {
    const FString InstructionName = Statement->GetStringField(TEXT("Inst"));

    if (InstructionName == TEXT("Nothing")) {
        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_Nop;
        return Result;
    }
    
    if (InstructionName == TEXT("SetSet")) {
        TArray<TSharedPtr<FJsonValue>> Values = Statement->GetArrayField(TEXT("Values"));
        const TSharedPtr<FJsonObject> LeftSideExpression = Statement->GetObjectField(TEXT("LeftSideExpression"));

        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_CreateSet;
        Result->LHS = ProcessExpression(LeftSideExpression);

        for (const TSharedPtr<FJsonValue>& Value : Values) {
            Result->RHS.Add(ProcessExpression(Value->AsObject()));
        }
        return Result;
    }

    if (InstructionName == TEXT("SetArray")) {
        TArray<TSharedPtr<FJsonValue>> Values = Statement->GetArrayField(TEXT("Values"));
        const TSharedPtr<FJsonObject> LeftSideExpression = Statement->GetObjectField(TEXT("LeftSideExpression"));

        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_CreateArray;
        Result->LHS = ProcessExpression(LeftSideExpression);

        for (const TSharedPtr<FJsonValue>& Value : Values) {
            Result->RHS.Add(ProcessExpression(Value->AsObject()));
        }
        return Result;
    }

    if (InstructionName == TEXT("SetMap")) {
        TArray<TSharedPtr<FJsonValue>> Values = Statement->GetArrayField(TEXT("Values"));
        const TSharedPtr<FJsonObject> LeftSideExpression = Statement->GetObjectField(TEXT("LeftSideExpression"));

        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_CreateMap;
        Result->LHS = ProcessExpression(LeftSideExpression);

        //Maps are represented by (key, value) terms being followed by each other
        for (const TSharedPtr<FJsonValue>& Value : Values) {
            const TSharedPtr<FJsonObject> PairObject = Value->AsObject();
            Result->RHS.Add(ProcessExpression(PairObject->GetObjectField(TEXT("Key"))));
            Result->RHS.Add(ProcessExpression(PairObject->GetObjectField(TEXT("Value"))));
        }
        return Result;
    }

    //All of the assignment instructions are similar, it's just that they are type-specific for runtime to have easier time handling them
    if (InstructionName == TEXT("Let") || InstructionName == TEXT("LetObj") ||
        InstructionName == TEXT("LetWeakObjPtr") || InstructionName == TEXT("LetBool") ||
        InstructionName == TEXT("LetMulticastDelegate") || InstructionName == TEXT("LetDelegate")) {

        const TSharedPtr<FJsonObject> Variable = Statement->GetObjectField(TEXT("Variable"));
        const TSharedPtr<FJsonObject> Expression = Statement->GetObjectField(TEXT("Expression"));
        const FString ExpressionInstName = Expression->GetStringField(TEXT("Inst"));
        
        //Function calls cannot be expressions in compiled statement representation, so we need to handle case of RHS being CallFunction here
        //They often happen to be prefixed with a context expression (except math call, which doesn't need context)
        //So we need to check for both context expression and call function instruction
        //ProcessFunctionCallStatement will handle context expression itself just fine too, so just call it regardless
        if (IsCallFunctionInstruction(ExpressionInstName) || IsContextInstruction(ExpressionInstName)) {
            TSharedPtr<FKismetCompiledStatement> FunctionCall = ProcessFunctionCallStatement(Expression);
            if (!FunctionCall.IsValid()) {
                return nullptr;   // unresolved call → degrade this assignment (driver skips null statements)
            }
            //Set LHS so that function call result will be saved into the variable
            FunctionCall->LHS = ProcessExpression(Variable);
            return FunctionCall;
        }

        //Casts are compiled down to variable assignments, so we need to handle them there

        //These two cases below handle FScriptInterface <-> UObject pointer conversions primarily
        if (ExpressionInstName == TEXT("ObjToInterfaceCast") || ExpressionInstName == TEXT("CrossInterfaceCast")) {
            TSharedPtr<FKismetCompiledStatement> InterfaceCast = MakeShareable(new FKismetCompiledStatement());

            //Wraps UObject pointer into the FScriptInterface with provided interface class
            if (ExpressionInstName == TEXT("ObjToInterfaceCast")) {
                InterfaceCast->Type = ECompiledStatementType::KCST_CastObjToInterface; 
            //Converts FScriptInterface pointer to one interface into another at the same object
            } else if (ExpressionInstName == TEXT("CrossInterfaceCast")) {
                InterfaceCast->Type = ECompiledStatementType::KCST_CrossInterfaceCast;
            } else {
                //Unreachable while the enclosing `if` admits exactly these two names — degrade anyway, so widening
                //that condition can never turn into a fatal on the sweep path.
                UE_LOG(LogTemp, Warning, TEXT("[MifKR] Unknown interface cast instruction (deferred): %s"), *ExpressionInstName);
                return nullptr;
            }
                
            const FString InterfaceClassPath = Expression->GetStringField(TEXT("InterfaceClass"));
            const TSharedPtr<FJsonObject> InnerExpression = Expression->GetObjectField(TEXT("Expression"));
            
            UClass* InterfaceClass = LoadObject<UClass>(NULL, *InterfaceClassPath);
            if (!InterfaceClass) return nullptr;   // unresolved interface class → degrade
            
            TSharedPtr<FKismetTerminal> ClassLiteral = MakeShareable(new FKismetTerminal());
            
            ClassLiteral->bIsLiteral = true;
            ClassLiteral->Type.PinCategory = UEdGraphSchema_K2::PC_Class;
            ClassLiteral->Type.PinSubCategoryObject = InterfaceClass;
            ClassLiteral->ObjectLiteral = InterfaceClass;
            
            InterfaceCast->LHS = ProcessExpression(Variable);
            InterfaceCast->RHS.Add(ClassLiteral);
            InterfaceCast->RHS.Add(ProcessExpression(InnerExpression));
            return InterfaceCast;
        }

        //Converts FScriptInterface object to raw UObject pointer
        if (ExpressionInstName == TEXT("InterfaceToObjCast")) {
            TSharedPtr<FKismetCompiledStatement> InterfaceToObjCast = MakeShareable(new FKismetCompiledStatement());
            InterfaceToObjCast->Type = ECompiledStatementType::KCST_CastInterfaceToObj;
                
            const FString ObjectClassPath = Expression->GetStringField(TEXT("ObjectClass"));
            const TSharedPtr<FJsonObject> InnerExpression = Expression->GetObjectField(TEXT("Expression"));
            
            UClass* ObjectClass = LoadObject<UClass>(NULL, *ObjectClassPath);
            if (!ObjectClass) return nullptr;   // unresolved object class → degrade
            
            TSharedPtr<FKismetTerminal> ClassLiteral = MakeShareable(new FKismetTerminal());
            ClassLiteral->bIsLiteral = true;
            ClassLiteral->Type.PinCategory = UEdGraphSchema_K2::PC_Class;
            ClassLiteral->Type.PinSubCategoryObject = ObjectClass;
            ClassLiteral->ObjectLiteral = ObjectClass;
            
            InterfaceToObjCast->LHS = ProcessExpression(Variable);
            InterfaceToObjCast->RHS.Add(ClassLiteral);
            InterfaceToObjCast->RHS.Add(ProcessExpression(InnerExpression));
            return InterfaceToObjCast;
        }

        //These casts handle conversion between UObject pointer types and do not invole interfaces
        if (ExpressionInstName == TEXT("DynamicCast") || ExpressionInstName == TEXT("MetaCast")) {
            TSharedPtr<FKismetCompiledStatement> CastStatement = MakeShareable(new FKismetCompiledStatement());

            //DynamicCast handles conversions between UObject types (except UClasses)
            if (ExpressionInstName == TEXT("DynamicCast")) {
                CastStatement->Type = ECompiledStatementType::KCST_DynamicCast;
            //MetaCast handles conversion between UClass types (actually it only does class type checking)
            } else if (ExpressionInstName == TEXT("MetaCast")) {
                CastStatement->Type = ECompiledStatementType::KCST_MetaCast;
            } else {
                //As above: unreachable today, degraded rather than fatal so it stays that way.
                UE_LOG(LogTemp, Warning, TEXT("[MifKR] Unsupported cast instruction (deferred): %s"), *ExpressionInstName);
                return nullptr;
            }
                
            const FString DestinationClassPath = Expression->GetStringField(TEXT("Class"));
            const TSharedPtr<FJsonObject> InnerExpression = Expression->GetObjectField(TEXT("Expression"));
            
            UClass* DestinationClass = LoadObject<UClass>(NULL, *DestinationClassPath);
            if (!DestinationClass) return nullptr;   // unresolved cast target class → degrade
            
            TSharedPtr<FKismetTerminal> ClassLiteral = MakeShareable(new FKismetTerminal());
            ClassLiteral->bIsLiteral = true;
            ClassLiteral->Type.PinCategory = UEdGraphSchema_K2::PC_Class;
            ClassLiteral->Type.PinSubCategoryObject = DestinationClass;
            ClassLiteral->ObjectLiteral = DestinationClass;
            
            CastStatement->LHS = ProcessExpression(Variable);
            CastStatement->RHS.Add(ClassLiteral);
            CastStatement->RHS.Add(ProcessExpression(InnerExpression));
            return CastStatement;
        }

        //PrimitiveCast converts UObject/FScriptInterface objects into boolean, and (UE5) also does numeric LWC
        //conversions (DoubleToFloat/FloatToDouble) and ObjectToInterface.
        if (ExpressionInstName == TEXT("PrimitiveCast")) {
            const TSharedPtr<FJsonObject> InnerExpression = Expression->GetObjectField(TEXT("Expression"));
            const FString CastType = Expression->GetStringField(TEXT("CastType"));

            TSharedPtr<FKismetCompiledStatement> PrimitiveCast = MakeShareable(new FKismetCompiledStatement());
            if (CastType == TEXT("InterfaceToBool") || CastType == TEXT("ObjectToBool")) {
                PrimitiveCast->Type = ECompiledStatementType::KCST_ObjectToBool;
            } else {
                //Other primitive conversions (numeric LWC DoubleToFloat/FloatToDouble, ObjectToInterface, …) —
                //reconstruct as a plain pass-through assignment; the pin types carry the conversion. Don't crash.
                PrimitiveCast->Type = ECompiledStatementType::KCST_Assignment;
            }
            PrimitiveCast->LHS = ProcessExpression(Variable);
            PrimitiveCast->RHS.Add(ProcessExpression(InnerExpression));
            return PrimitiveCast;
        }
        
        //Otherwise it is a normal assignment operation, so right side should be a simple expression
        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_Assignment;
        Result->LHS = ProcessExpression(Variable);
        Result->RHS.Add(ProcessExpression(Expression));
        return Result;
    }

    if (InstructionName == TEXT("LetValueOnPersistentFrame")) {
        //It is variable assignment on a persistent frame, just like a normal assignment, but dest property is a bit special
        const TSharedPtr<FJsonObject> Expression = Statement->GetObjectField(TEXT("Expression"));
        const TSharedPtr<FJsonObject> PropertyType = Statement->GetObjectField(TEXT("PropertyType"));
        const FString PropertyName = Statement->GetStringField(TEXT("PropertyName"));
        
        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_AssignmentOnPersistentFrame;

        //Deserialize type from instruction data directly, because figuring out persistent frame layout is hard
        //from this point by variable name inside it. It's much easier just to read pre-recorded information
        Result->LHS = MakeShareable(new FKismetTerminal());
        Result->LHS->Type = FPropertyTypeHelper::DeserializeGraphPinType(PropertyType.ToSharedRef(), GetTypeSelfScope());
        Result->LHS->AssociatedVarProperty = PropertyName;

        Result->RHS.Add(ProcessExpression(Expression));
        return Result;
    }

    //This is a function call statement, possibly prefixed with context expressions
    //Just call process function call, it will handle the case when actual statement passed
    //is a context and not the function call node itself gracefully
    if (IsCallFunctionInstruction(InstructionName) || IsContextInstruction(InstructionName)) {
        return ProcessFunctionCallStatement(Statement);
    }

    //EX_CallMulticastDelegate will never be prefixed with context,
    //because it always accepts context as an separate argument and does not need it passed implicitly
    if (InstructionName == TEXT("CallMulticastDelegate")) {
        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_CallDelegate;
        Result->FunctionContext = ProcessExpression(Statement->GetObjectField(TEXT("Delegate")));

        const TSharedPtr<FJsonObject> DelegateSignatureFunctionRef = Statement->GetObjectField(TEXT("DelegateSignatureFunction"));
        if (!DelegateSignatureFunctionRef.IsValid()) return nullptr;

        const bool bIsSelfContext = DelegateSignatureFunctionRef->GetBoolField(TEXT("IsSelfContext"));
        const FString MemberName = DelegateSignatureFunctionRef->GetStringField(TEXT("MemberName"));

        UClass* MemberParentClass;

        //Resolve MemberParent class in respect to Self Context
        if (!bIsSelfContext) {
            const FString MemberParentPath = DelegateSignatureFunctionRef->GetStringField(TEXT("MemberParent"));
            MemberParentClass = LoadObject<UClass>(NULL, *MemberParentPath);
        } else {
            //In self context, we should use skeleton blueprint class as a member parent
            MemberParentClass = OwnerBlueprint->SkeletonGeneratedClass;
        }

        //The F3 editable copy SKIPS delegate member variables, so a self-delegate's signature may not exist on the
        //reconstructed class → soft-degrade (skip the broadcast) instead of crashing the whole sweep.
        UFunction* Function = MemberParentClass ? MemberParentClass->FindFunctionByName(*MemberName) : nullptr;
        if (!Function || !Function->HasAnyFunctionFlags(FUNC_Delegate)) return nullptr;

        Result->FunctionToCall = Function;

        //Do argument processing that is common for all function call instructions
        TArray<TSharedPtr<FJsonValue>> Parameters = Statement->GetArrayField(TEXT("Parameters"));

        int32 NumParams = 0;
        for (TFieldIterator<FProperty> PropIt(Result->FunctionToCall); PropIt && (PropIt->PropertyFlags & CPF_Parm); ++PropIt) {
           FProperty* FuncParamProperty = *PropIt;

            //Skip return values because they are handled in a special way when we happened to be an expression in EX_Let statement
            if (!FuncParamProperty->HasAnyPropertyFlags(CPF_ReturnParm)) {
                if (!Parameters.IsValidIndex(NumParams)) return nullptr;   // signature/JSON param-count mismatch → degrade
                const TSharedPtr<FJsonObject> ParameterExpression = Parameters[NumParams++]->AsObject();
                TSharedPtr<FKismetTerminal> ParameterTerminal = ProcessFunctionParameter(ParameterExpression);

                Result->RHS.Add(ParameterTerminal);
            }
        }
        return Result;
    }

    //This is a computed jump statement, offset expression should be stored in the LHS
    if (InstructionName == TEXT("ComputedJump")) {
        const TSharedPtr<FJsonObject> Expression = Statement->GetObjectField(TEXT("Expression"));
        
        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_ComputedGoto;
        Result->LHS = ProcessExpression(Expression);
        return Result;
    }

    //This is an unconditional jump, offset is stored in the TargetLabel
    //But we cannot really resolve it until we finished processing all statements, so store it in the patch-up map
    if (InstructionName == TEXT("Jump")) {
        const int32 JumpOffset = Statement->GetIntegerField(TEXT("Offset"));
        
        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_UnconditionalGoto;
        JumpPatchUpTable.Add(Result, JumpOffset);
        return Result;
    }

    if (InstructionName == TEXT("JumpIfNot")) {
        const TSharedPtr<FJsonObject> Condition = Statement->GetObjectField(TEXT("Condition"));
        const int32 JumpOffset = Statement->GetIntegerField(TEXT("Offset"));
        
        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_GotoIfNot;
        Result->LHS = ProcessExpression(Condition);
        JumpPatchUpTable.Add(Result, JumpOffset);
        return Result;
    }

    //Adds the location at which code will jump once PopExecutionFlow is encountered
    if (InstructionName == TEXT("PushExecutionFlow")) {
        const int32 JumpOffset = Statement->GetIntegerField(TEXT("Offset"));
        
        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_PushState;
        JumpPatchUpTable.Add(Result, JumpOffset);
        return Result;
    }

    //Pops execution flow to the last stored location (or to return statement) if condition is zero
    if (InstructionName == TEXT("PopExecutionFlowIfNot")) {
        const TSharedPtr<FJsonObject> Condition = Statement->GetObjectField(TEXT("Condition"));
        
        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_EndOfThreadIfNot;
        Result->LHS = ProcessExpression(Condition);
        return Result;
    }

    //Pops execution flow to the last stored location (or to return statement) unconditionally
    if (InstructionName == TEXT("PopExecutionFlow")) {
        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_EndOfThread;
        return Result;
    }

    //Registers a delegate object into the multicast delegate subscription list
    if (InstructionName == TEXT("AddMulticastDelegate")) {
        const TSharedPtr<FJsonObject> MulticastDelegate = Statement->GetObjectField(TEXT("MulticastDelegate"));
        const TSharedPtr<FJsonObject> Delegate = Statement->GetObjectField(TEXT("Delegate"));

        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_AddMulticastDelegate;
        Result->LHS = ProcessExpression(MulticastDelegate);
        Result->RHS.Add(ProcessExpression(Delegate));
        return Result;
    }

    //Removes a single delegate object out of multicast delegate subscription list
    if (InstructionName == TEXT("RemoveMulticastDelegate")) {
        const TSharedPtr<FJsonObject> MulticastDelegate = Statement->GetObjectField(TEXT("MulticastDelegate"));
        const TSharedPtr<FJsonObject> Delegate = Statement->GetObjectField(TEXT("Delegate"));

        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_RemoveMulticastDelegate;
        Result->LHS = ProcessExpression(MulticastDelegate);
        Result->RHS.Add(ProcessExpression(Delegate));
        return Result;
    }

    //Clears a multicast delegate subscription list
    if (InstructionName == TEXT("ClearMulticastDelegate")) {
        const TSharedPtr<FJsonObject> MulticastDelegate = Statement->GetObjectField(TEXT("MulticastDelegate"));
        
        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_ClearMulticastDelegate;
        Result->LHS = ProcessExpression(MulticastDelegate);
        return Result;
    }

    //Populates delegate object expression with a reference to the function of the object passed
    if (InstructionName == TEXT("BindDelegate")) {
        const TSharedPtr<FJsonObject> Delegate = Statement->GetObjectField(TEXT("Delegate"));
        const TSharedPtr<FJsonObject> Object = Statement->GetObjectField(TEXT("Object"));
        const FString FunctionName = Statement->GetStringField(TEXT("FunctionName"));

        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_BindDelegate;
        Result->LHS = ProcessExpression(Delegate);

        //Create string literal with function name and add it as the first argument
        TSharedPtr<FKismetTerminal> FunctionNameTerminal = MakeShareable(new FKismetTerminal());
        FunctionNameTerminal->bIsLiteral = true;
        FunctionNameTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Name;
        FunctionNameTerminal->StringLiteral = FunctionName;
        Result->RHS.Add(FunctionNameTerminal);
        
        Result->RHS.Add(ProcessExpression(Object));
        return Result;
    }

    //Returns from the currently running function, optionally passing back returned value (or nothing)
    if (InstructionName == TEXT("Return")) {
        TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
        Result->Type = ECompiledStatementType::KCST_Return;
        return Result;
    }

    //Catch-all: an unhandled statement opcode degrades to a null statement the driver skips — never crash the sweep.
    UE_LOG(LogTemp, Warning, TEXT("[MifKR] Unhandled statement instruction (deferred): %s"), *InstructionName);
    return nullptr;
}

TSharedPtr<FKismetTerminal> FKismetBytecodeTransformer::ProcessExpression(TSharedPtr<FJsonObject> Expression) {
    const FString InstructionName = Expression->GetStringField(TEXT("Inst"));

    //InlineGeneratedParameter will always be NULL for terminals returned by ProcessExpression,
    //since we just don't have enough context to process statements here, and
    //it can only be encountered inside of the CallFunction statements - so we handle it there

    //EX_StructMemberContext retrieves value of struct property from struct value passed as context
    if (InstructionName == TEXT("StructMemberContext")) {
        const FString PropertyName = Expression->GetStringField(TEXT("PropertyName"));
        const TSharedPtr<FJsonObject> PropertyType = Expression->GetObjectField(TEXT("PropertyType"));
        const TSharedPtr<FJsonObject> ContextExpression = Expression->GetObjectField(TEXT("StructExpression"));

        const TSharedPtr<FKismetTerminal> ContextTerminal = ProcessExpression(ContextExpression);
        if (!ContextTerminal.IsValid()) return nullptr;   // struct-context inner degraded (ArrayGetByRef / unresolved literal) — don't deref null
        ContextTerminal->ContextType = FKismetTerminal::EContextType_Struct;
        
        TSharedPtr<FKismetTerminal> StructMemberTerminal = MakeShareable(new FKismetTerminal());
        StructMemberTerminal->Type = FPropertyTypeHelper::DeserializeGraphPinType(PropertyType.ToSharedRef(), GetTypeSelfScope());
        StructMemberTerminal->AssociatedVarProperty = PropertyName;

        StructMemberTerminal->Context = ContextTerminal;
        
        return StructMemberTerminal;
    }

    //EX_Context, EX_Context_FailSilent and EX_ClassContext are all indicate nested expression run inside of the context
    if (IsContextInstruction(InstructionName)) {
        const bool bIsClassContext = InstructionName == TEXT("ClassContext");
        const TSharedPtr<FJsonObject> Context = Expression->GetObjectField(TEXT("Context"));
        const TSharedPtr<FJsonObject> InnerExpression = Expression->GetObjectField(TEXT("Expression"));

        TSharedPtr<FKismetTerminal> ContextTerminal = ProcessExpression(Context);
        if (!ContextTerminal.IsValid()) return nullptr;   // context object degraded (call result / unresolved const) — don't deref null
        ContextTerminal->ContextType = bIsClassContext ? FKismetTerminal::EContextType_Class : FKismetTerminal::EContextType_Object;
        
        TSharedPtr<FKismetTerminal> InnerExpressionTerminal = ProcessExpression(InnerExpression);
        if (!InnerExpressionTerminal.IsValid()) return nullptr;   // inner expr degraded (unhandled call / unresolved const) — don't deref null
        InnerExpressionTerminal->Context = ContextTerminal;
        return InnerExpressionTerminal;
    }

    //EX_LocalVariable, EX_LocalOutVariable, EX_InstanceVariable and EX_DefaultVariable are all simple terminals with different VarType values
    if (IsVariableInstruction(InstructionName)) {
        const FString VariableName = Expression->GetStringField(TEXT("VariableName"));
        const TSharedPtr<FJsonObject> VariableType = Expression->GetObjectField(TEXT("VariableType"));

        //We can resolve type of variable by simply looking up through properties associated with UFunction, but it's much easier to read pre-recorded information
        TSharedPtr<FKismetTerminal> VariableTerminal = MakeShareable(new FKismetTerminal());
        VariableTerminal->Type = FPropertyTypeHelper::DeserializeGraphPinType(VariableType.ToSharedRef(), GetTypeSelfScope());
        VariableTerminal->AssociatedVarProperty = VariableName;

        if (InstructionName == TEXT("DefaultVariable")) {
            VariableTerminal->VarType = FKismetTerminal::EVarType_Default;
        } else if (InstructionName == TEXT("InstanceVariable")) {
            VariableTerminal->VarType = FKismetTerminal::EVarType_Instanced;
        } else if (InstructionName == TEXT("LocalVariable") || InstructionName == TEXT("LocalOutVariable")) {
            //LocalOutVariable will be generated if Property in question has CPF_Out flag and is an out property
            VariableTerminal->VarType = FKismetTerminal::EVarType_Local;
        } else {
            //Unreachable while IsVariableInstruction() admits exactly the four names handled above. Degrade rather
            //than fatal: an unknown VarType would produce a wrong terminal anyway, and null is the driver's skip.
            UE_LOG(LogTemp, Warning, TEXT("[MifKR] Unhandled variable instruction (deferred): %s"), *InstructionName);
            return nullptr;
        }
        return VariableTerminal;
    }

    //Should be a literal now
    return ProcessLiteralExpression(Expression, false);
}

TSharedPtr<FKismetTerminal> FKismetBytecodeTransformer::ProcessLiteralExpression(TSharedPtr<FJsonObject> Expression, bool bIsDelimited) {
    const FString InstructionName = Expression->GetStringField(TEXT("Inst"));
    
    TSharedPtr<FKismetTerminal> LiteralTerminal = MakeShareable(new FKismetTerminal());
    LiteralTerminal->bIsLiteral = true;

    //Basically represents the current Context UObject and allows retrieval of it
    //We record just as the type meta information, actual string and object literals will be empty
    if (InstructionName == TEXT("Self")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Object;
        LiteralTerminal->Type.PinSubCategory = UEdGraphSchema_K2::PSC_Self;
        return LiteralTerminal;
    }

    //Text literals, pretty complicated in serialization because of existence of multiple types
    if (InstructionName == TEXT("TextConst")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Text;
        const FString LiteralType = Expression->GetStringField(TEXT("TextLiteralType"));
        
        if (LiteralType == TEXT("Empty")) {
            LiteralTerminal->TextLiteral = FText::GetEmpty();
            
        } else if (LiteralType == TEXT("LocalizedText")) {
            const FString SourceString = Expression->GetStringField(TEXT("SourceString"));
            const FString KeyString = Expression->GetStringField(TEXT("LocalizationKey"));
            const FString Namespace = Expression->GetStringField(TEXT("LocalizationNamespace"));
            const FText Text = FInternationalization::ForUseOnlyByLocMacroAndGraphNodeTextLiterals_CreateText(*SourceString, *Namespace, *KeyString);
            LiteralTerminal->TextLiteral = Text;
            
        } else if (LiteralType == TEXT("InvariantText")) {
            const FString SourceString = Expression->GetStringField(TEXT("SourceString"));
            LiteralTerminal->TextLiteral = FText::AsCultureInvariant(SourceString);
            
        } else if (LiteralType == TEXT("LiteralString")) {
            const FString SourceString = Expression->GetStringField(TEXT("SourceString"));
            LiteralTerminal->TextLiteral = FText::FromString(SourceString);
            
        } else if (LiteralType == TEXT("StringTableEntry")) {
            const FString TableId = Expression->GetStringField(TEXT("TableId"));
            const FString TableKey = Expression->GetStringField(TEXT("TableKey"));
            LiteralTerminal->TextLiteral = FText::FromStringTable(*TableId, *TableKey);
        }

        //Also serialize text in UTextProperty format and fill StringLiteral, just to support uniform ImportText calls on FKismetTerminal objects
        FString StringLiteralValue;
        FTextStringHelper::WriteToBuffer(StringLiteralValue, LiteralTerminal->TextLiteral, bIsDelimited);
        LiteralTerminal->StringLiteral = StringLiteralValue;
        
        return LiteralTerminal;
    }

    //String Literal encoded as ASCII, containing only characters of ASCII range
    if (InstructionName == TEXT("StringConst")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_String;
        LiteralTerminal->StringLiteral = Expression->GetStringField(TEXT("Value"));

        if (bIsDelimited) {
            LiteralTerminal->StringLiteral = FString::Printf(TEXT("\"%s\""), *(LiteralTerminal->StringLiteral.ReplaceCharWithEscapedChar()));
        }
        return LiteralTerminal;
    }
    
    //String Literal containing unicode characters
    if (InstructionName == TEXT("UnicodeStringConst")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_String;
        LiteralTerminal->StringLiteral = Expression->GetStringField(TEXT("Value"));

        if (bIsDelimited) {
            LiteralTerminal->StringLiteral = FString::Printf(TEXT("\"%s\""), *(LiteralTerminal->StringLiteral.ReplaceCharWithEscapedChar()));
        }
        return LiteralTerminal;
    }

    //Floating point number constant (in terminal form, it is stored in string literal field)
    if (InstructionName == TEXT("FloatConst") || InstructionName == TEXT("DoubleConst")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Real; LiteralTerminal->Type.PinSubCategory = (InstructionName == TEXT("DoubleConst")) ? UEdGraphSchema_K2::PC_Double : UEdGraphSchema_K2::PC_Float;
        LiteralTerminal->StringLiteral = FString::Printf(TEXT("%f"), Expression->GetNumberField(TEXT("Value")));
        return LiteralTerminal;
    }
    
    //Integer number constant (in terminal form, it is stored in string literal field)
    if (InstructionName == TEXT("IntConst")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Int;
        LiteralTerminal->StringLiteral = FString::FromInt(Expression->GetIntegerField(TEXT("Value")));
        return LiteralTerminal;
    }
    
    //64-bit integer number constant, recorded as string in JSON because double cannot represent entire value range on 64-bit integer
    if (InstructionName == TEXT("Int64Const")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Int64;
        LiteralTerminal->StringLiteral = Expression->GetStringField(TEXT("Value"));
        return LiteralTerminal;
    }
    
    //Unsigned 64-bit integer number constant, never emitted because there is no Kismet graph type for it
    //No way to represent UInt64 in Kismet pin type hierarchy, so record it as int64 which will be converted back if needed
    if (InstructionName == TEXT("UInt64Const")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Int64;
        LiteralTerminal->StringLiteral = Expression->GetStringField(TEXT("Value"));
        return LiteralTerminal;
    }
    
    //TODO Enums in Kismet are represented as byte constants, since Kismet only supports byte enums
    //TODO we just don't have information to reconstruct original kismet type there, so we record it as byte
    if (InstructionName == TEXT("ByteConst")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Byte;
        LiteralTerminal->StringLiteral = FString::FromInt(Expression->GetIntegerField(TEXT("Value")));
        return LiteralTerminal;
    }

    //Convert boolean constant instructions EX_False and EX_True
    if (InstructionName == TEXT("False")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Boolean;
        LiteralTerminal->StringLiteral = TEXT("0");
        return LiteralTerminal;
    }
    if (InstructionName == TEXT("True")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Boolean;
        LiteralTerminal->StringLiteral = TEXT("1");
        return LiteralTerminal;
    }

    //Name constant, mostly similar to string literal but represents an FName object instead
    if (InstructionName == TEXT("NameConst")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Name;
        LiteralTerminal->StringLiteral = Expression->GetStringField(TEXT("Value"));

        if (bIsDelimited) {
            LiteralTerminal->StringLiteral = FString::Printf(TEXT("\"%s\""), *LiteralTerminal->StringLiteral.ReplaceCharWithEscapedChar());
        }
        return LiteralTerminal;
    }
    
    //Vector constant, basically a specialized version of StructConst with the same format
    if (InstructionName == TEXT("VectorConst")) {
        FVector VectorConst(Expression->GetNumberField(TEXT("X")), Expression->GetNumberField(TEXT("Y")), Expression->GetNumberField(TEXT("Z")));
        UScriptStruct* VectorStruct = TBaseStructure<FVector>::Get();
        
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Struct;
        LiteralTerminal->Type.PinSubCategoryObject = VectorStruct;
        int32 PortFlags = bIsDelimited ? PPF_Delimited : PPF_None;
        VectorStruct->ExportText(LiteralTerminal->StringLiteral, &VectorConst, NULL, NULL, PortFlags, NULL);
        return LiteralTerminal;
    }

    //Rotation constant, basically a specialized version of StructConst with the same format
    if (InstructionName == TEXT("RotationConst")) {
        FRotator RotatorConst(Expression->GetNumberField(TEXT("Pitch")), Expression->GetNumberField(TEXT("Yaw")), Expression->GetNumberField(TEXT("Roll")));
        UScriptStruct* RotatorStruct = TBaseStructure<FRotator>::Get();

        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Struct;
        LiteralTerminal->Type.PinSubCategoryObject = RotatorStruct;
        int32 PortFlags = bIsDelimited ? PPF_Delimited : PPF_None;
        RotatorStruct->ExportText(LiteralTerminal->StringLiteral, &RotatorConst, NULL, NULL, PortFlags, NULL);
        return LiteralTerminal;
    }

    //Transform constant, a combination of rotation, translation and scale components
    if (InstructionName == TEXT("TransformConst")) {
        const TSharedPtr<FJsonObject> RotationObj = Expression->GetObjectField(TEXT("Rotation"));
        FQuat Rotation = FQuat(RotationObj->GetNumberField(TEXT("X")), RotationObj->GetNumberField(TEXT("Y")), RotationObj->GetNumberField(TEXT("Z")), RotationObj->GetNumberField(TEXT("W")));

        const TSharedPtr<FJsonObject> TranslationObj = Expression->GetObjectField(TEXT("Translation"));
        FVector Translation = FVector(TranslationObj->GetNumberField(TEXT("X")), TranslationObj->GetNumberField(TEXT("Y")), TranslationObj->GetNumberField(TEXT("Z")));

        const TSharedPtr<FJsonObject> ScaleObj = Expression->GetObjectField(TEXT("Scale"));
        FVector Scale = FVector(ScaleObj->GetNumberField(TEXT("X")), ScaleObj->GetNumberField(TEXT("Y")), ScaleObj->GetNumberField(TEXT("Z")));

        FTransform ResultTransform(Rotation, Translation, Scale);
        UScriptStruct* TransformStruct = TBaseStructure<FTransform>::Get();

        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Struct;
        LiteralTerminal->Type.PinSubCategoryObject = TransformStruct;
        int32 PortFlags = bIsDelimited ? PPF_Delimited : PPF_None;
        TransformStruct->ExportText(LiteralTerminal->StringLiteral, &ResultTransform, NULL, NULL, PortFlags, NULL);
        return LiteralTerminal;
    }

    //Struct constant, needs to be serialized as string
    if (InstructionName == TEXT("StructConst")) {
        const FString StructPathName = Expression->GetStringField(TEXT("Struct"));
        TSharedPtr<FJsonObject> Properties = Expression->GetObjectField(TEXT("Properties"));
        
        UScriptStruct* ScriptStruct = LoadObject<UScriptStruct>(NULL, *StructPathName);
        if (!ScriptStruct) return nullptr;   // unresolved struct type → degrade, don't crash

        //Create temporary struct to hold deserialized values before serialization
        void* AllocatedStructInstance = FMemory::Malloc(ScriptStruct->GetPropertiesSize());
        ScriptStruct->InitializeStruct(AllocatedStructInstance);

        //Deserialize properties recorded in the struct constant by evaluating expressions
        for (const TPair<FString, TSharedPtr<FJsonValue>>& Pair : Properties->Values) {
            const TArray<TSharedPtr<FJsonValue>> PropertyValueArray = Pair.Value->AsArray();
            const FString& PropertyName = Pair.Key;
            FProperty* Property = ScriptStruct->FindPropertyByName(*PropertyName);
            if (!Property) continue;   // struct field not found (renamed/editor-only) → skip it, don't crash

            for (int32 ArrayIter = 0; ArrayIter < Property->ArrayDim; ++ArrayIter) {
                if (!PropertyValueArray.IsValidIndex(ArrayIter)) break;   // partial/aborted disassembly → fewer elements than ArrayDim; degrade, don't RangeCheck-crash
                const TSharedPtr<FJsonObject> PropertyValueExpression = PropertyValueArray[ArrayIter]->AsObject();
                const TSharedPtr<FKismetTerminal> PropertyValue = ProcessLiteralExpression(PropertyValueExpression, false);
                if (!PropertyValue.IsValid()) continue;   // struct field value unresolved (cooked-only/other-pak) → leave at InitializeStruct default, don't deref null

                //Thing is, all of the constant values are serialized in the way compatible in ImportText/ExportText
                //methods implementation on common property types. So we can just call ImportText with StringLiteral
                //and handle other types of constants manually
                if (FTextProperty* TextProperty = CastField<FTextProperty>(Property)) {
                    const FText& TextPropertyValue = PropertyValue->TextLiteral;
                    TextProperty->SetPropertyValue_InContainer(AllocatedStructInstance, TextPropertyValue, ArrayIter);
                    
                } else if (FObjectProperty* ObjectProperty = CastField<FObjectProperty>(Property)) {
                    UObject* ObjectPropertyValue = PropertyValue->ObjectLiteral;
                    ObjectProperty->SetPropertyValue_InContainer(AllocatedStructInstance, ObjectPropertyValue, ArrayIter);
                } else {
                    const TCHAR* LiteralPropertyValue = *PropertyValue->StringLiteral;
                    void* PropertyValuePtr = Property->ContainerPtrToValuePtr<void>(AllocatedStructInstance, ArrayIter);
                    Property->ImportText_Direct(LiteralPropertyValue, PropertyValuePtr, NULL, PPF_None);
                }
            }
        }

        //Call destructor or struct we allocated earlier and free memory
        FString ExportedStructureText;
        int32 PortFlags = bIsDelimited ? PPF_Delimited : PPF_None;
        ScriptStruct->ExportText(ExportedStructureText, AllocatedStructInstance, NULL, NULL, PortFlags, NULL);
        ScriptStruct->DestroyStruct(AllocatedStructInstance);
        FMemory::Free(AllocatedStructInstance);

        //Serialize struct back as text and set correct kismet type
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Struct;
        LiteralTerminal->Type.PinSubCategoryObject = ScriptStruct;
        LiteralTerminal->StringLiteral = ExportedStructureText;
        return LiteralTerminal;
    }

    //Delegate property, only possible constant value of delegate property is function bound to self
    //TODO we don't have enough information to determine type of delegate here, primarily because context is not available by the time we are called
    //TODO but even with context, best thing we could do is obtain function object for bound function, which does not automatically let us obtain reference to
    //TODO delegate signature function. Best thing we could do is correct the type when assigning delegate to variables/using it during function calls
    if (InstructionName == TEXT("InstanceDelegate")) {
        const FString FunctionName = Expression->GetStringField(TEXT("FunctionName"));
        
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Delegate; 
        LiteralTerminal->StringLiteral = FunctionName;
        return LiteralTerminal;
    }

    //Soft object constant. Expression will always be a string literal path to the object in question
    if (InstructionName == TEXT("SoftObjectConst")) {
        TSharedPtr<FJsonObject> ObjectPathExpression = Expression->GetObjectField(TEXT("Value"));
        TSharedPtr<FKismetTerminal> ObjectPathLiteral = ProcessLiteralExpression(ObjectPathExpression, false);
        //The inner literal can degrade to null (unsupported/unresolved const) — dereferencing it, or check()-ing the
        //category of a non-string inner expression, kills the editor mid-sweep. Degrade the SoftObject literal instead.
        if (!ObjectPathLiteral.IsValid() || ObjectPathLiteral->Type.PinCategory != UEdGraphSchema_K2::PC_String) {
            UE_LOG(LogTemp, Warning, TEXT("[MifKR] SoftObjectConst inner path is not a string literal (deferred)"));
            return nullptr;
        }
        const FString SoftObjectPath = ObjectPathLiteral->StringLiteral;

        //Attempt to set PinSubCategoryObject by loading asset and figuring out it's class
        UClass* LoadedObjectClass = UObject::StaticClass();
        if (!SoftObjectPath.IsEmpty()) {
            UObject* LoadedObject = LoadObject<UObject>(NULL, *SoftObjectPath);
            if (LoadedObject) {
                LoadedObjectClass = LoadedObject->GetClass();
            }
        }

        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_SoftObject;
        LiteralTerminal->Type.PinSubCategoryObject = LoadedObjectClass;
        LiteralTerminal->StringLiteral = ObjectPathLiteral->StringLiteral;
        return LiteralTerminal;
    }

    //EX_NoObject basically indicates NULL UObject pointer constant. We fill PinSubCategoryObject with UObject::StaticClass()
    //because we cannot really deduce type of generic NULL value without a context
    if (InstructionName == TEXT("NoObject")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Object;
        LiteralTerminal->Type.PinSubCategoryObject = UObject::StaticClass();
        LiteralTerminal->ObjectLiteral = NULL;
        LiteralTerminal->StringLiteral = TEXT("None");
        return LiteralTerminal;
    }

    //Object literal, points to the existing UObject either inside or outside of this asset
    if (InstructionName == TEXT("ObjectConst")) {
        const FString ObjectPath = Expression->GetStringField(TEXT("Object"));
        
        //Resolve referenced asset object
        UObject* ReferencedObject = LoadObject<UObject>(NULL, *ObjectPath);
        if (!ReferencedObject) return nullptr;   // cooked-only / renamed / other-pak asset → degrade, don't crash

        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Object;
        LiteralTerminal->Type.PinSubCategoryObject = ReferencedObject->GetClass();
        LiteralTerminal->ObjectLiteral = ReferencedObject;

        //Export object both as object literal and as text, needed for array serialization
        //Code below is copied from UObjectPropertyBase::ExportText, because provided literal will be used with ImportText later
        FString ObjectExportName = ReferencedObject->GetPathName();
        if (bIsDelimited) {
            ObjectExportName = FString::Printf(TEXT("\"%s\""), *ObjectExportName.ReplaceQuotesWithEscapedQuotes());
        }
        
        const FString ObjectTextPathName = FString::Printf(TEXT("%s'%s'"), *ReferencedObject->GetClass()->GetName(), *ObjectExportName);
        LiteralTerminal->StringLiteral = ObjectTextPathName;
        
        return LiteralTerminal;
    }

    //FScriptInterface literal, currently only NULL and Self objects can be represented as interface literals
    //TODO interface pin type is incomplete, because we cannot infer interface class type from NULL value
    if (InstructionName == TEXT("NoInterface")) {
        LiteralTerminal->Type.PinCategory = UEdGraphSchema_K2::PC_Interface;
        LiteralTerminal->ObjectLiteral = NULL;
        LiteralTerminal->StringLiteral = TEXT("None");
        return LiteralTerminal;   // was missing → every NoInterface literal fell through to the checkf(0) below
    }

    //Set and array constants are serialized in exactly the same way, by  using (X, Y, Z) format where X/Y/Z are delimited literals
    if (InstructionName == TEXT("ArrayConst") || InstructionName == TEXT("SetConst")) {
        //We know exact element type because it is recorded in the bytecode
        const TSharedPtr<FJsonObject> InnerPropertyObject = Expression->GetObjectField(TEXT("InnerProperty"));
        const TArray<TSharedPtr<FJsonValue>> Values = Expression->GetArrayField(TEXT("Values"));

        //Set array type from recorded instruction, container type is either a set or an array (depending on the opcode)
        FEdGraphPinType ArrayPropertyType = FPropertyTypeHelper::DeserializeGraphPinType(InnerPropertyObject.ToSharedRef(), GetTypeSelfScope());
        if (InstructionName == TEXT("ArrayConst")) {
            ArrayPropertyType.ContainerType = EPinContainerType::Array;
        } else {
            ArrayPropertyType.ContainerType = EPinContainerType::Set;
        }
        LiteralTerminal->Type = ArrayPropertyType;

        //Build a literal with all elements inside
        FString ArrayBuilderString = TEXT("(");
        int32 CurrentIndex = 0;
        
        for (const TSharedPtr<FJsonValue>& ValueExpression : Values) {
            //We need value constant delimited, because we are building the array literal string
            const TSharedPtr<FKismetTerminal> ValueConstant = ProcessLiteralExpression(ValueExpression->AsObject(), true);
            if (!ValueConstant.IsValid()) return nullptr;   // element unresolved (cooked-only/other-pak const) → degrade whole array/set literal
            check(ValueConstant->bIsLiteral);
            
            if (CurrentIndex++ != 0) {
                ArrayBuilderString.Append(TEXT(","));
            }
            ArrayBuilderString.Append(ValueConstant->StringLiteral);
        }
        
        ArrayBuilderString += TEXT(")");
        LiteralTerminal->StringLiteral = ArrayBuilderString;
        return LiteralTerminal;
    }

    //Map constants are very similar to set and array constants, we have specific types for them too,
    //and generally they have the same format, with entries recorded as pairs of (key, value)
    if (InstructionName == TEXT("MapConst")) {
        const TSharedPtr<FJsonObject> KeyPropertyObject = Expression->GetObjectField(TEXT("KeyProperty"));
        const TSharedPtr<FJsonObject> ValuePropertyObject = Expression->GetObjectField(TEXT("ValueProperty"));
        const TArray<TSharedPtr<FJsonValue>> Values = Expression->GetArrayField(TEXT("Values"));

        //Set map type from two recorded key and value pin types
        FEdGraphPinType ValuePropertyType = FPropertyTypeHelper::DeserializeGraphPinType(ValuePropertyObject.ToSharedRef(), GetTypeSelfScope());
        FEdGraphPinType KeyPropertyType = FPropertyTypeHelper::DeserializeGraphPinType(KeyPropertyObject.ToSharedRef(), GetTypeSelfScope());
        
        FEdGraphPinType MapPropertyType = KeyPropertyType;
        MapPropertyType.PinValueType = FEdGraphTerminalType::FromPinType(ValuePropertyType);
        MapPropertyType.ContainerType = EPinContainerType::Map;
        LiteralTerminal->Type = MapPropertyType;

        //Build a literal with all elements inside
        FString MapPairBuilderString = TEXT("(");
        int32 CurrentIndex = 0;

        //Serialize values into the delimited string
        for (const TSharedPtr<FJsonValue>& PairObject : Values) {
            //Object will contain key and value expressions, both of which should be literals
            const TSharedPtr<FJsonObject> KeyExpressionObject = PairObject->AsObject()->GetObjectField(TEXT("Key"));
            const TSharedPtr<FJsonObject> ValueExpressionObject = PairObject->AsObject()->GetObjectField(TEXT("Value"));

            const TSharedPtr<FKismetTerminal> KeyTerminal = ProcessLiteralExpression(KeyExpressionObject, true);
            const TSharedPtr<FKismetTerminal> ValueTerminal = ProcessLiteralExpression(ValueExpressionObject, true);
            if (!KeyTerminal.IsValid() || !ValueTerminal.IsValid()) return nullptr;   // key/value unresolved (cooked-only/other-pak const) → degrade whole map literal
            check(KeyTerminal->bIsLiteral);
            check(ValueTerminal->bIsLiteral);

            if (CurrentIndex++ != 0) {
                MapPairBuilderString.Append(TEXT(","));
            }

            MapPairBuilderString += TEXT("(");
            MapPairBuilderString.Append(KeyTerminal->StringLiteral);
            
            MapPairBuilderString += TEXT(", ");
            
            MapPairBuilderString.Append(ValueTerminal->StringLiteral);
            MapPairBuilderString += TEXT(")");
        }

        MapPairBuilderString += TEXT(")");
        LiteralTerminal->StringLiteral = MapPairBuilderString;
        return LiteralTerminal;
    }

    //Unknown literal type: degrade to a null terminal the caller handles, don't abort the editor.
    UE_LOG(LogTemp, Warning, TEXT("[MifKR] Unsupported literal instruction (deferred): %s"), *InstructionName);
    return nullptr;
}

TSharedPtr<FKismetCompiledStatement> FKismetBytecodeTransformer::ProcessFunctionCallStatement(TSharedPtr<FJsonObject> Statement)
{
    TSharedPtr<FKismetTerminal> Context;
    bool bIsInterfaceContext = false;

    //If expression we got is actually a context expression and not a direct function call, unwrap it and record context expression
    const FString InitialInstName = Statement->GetStringField(TEXT("Inst"));
    if (IsContextInstruction(InitialInstName)) {
        const bool bIsClassContext = InitialInstName == TEXT("ClassContext");
        TSharedPtr<FJsonObject> ContextObject = Statement->GetObjectField(TEXT("Context"));
        
        //Context expression will be prefixed with EX_InterfaceContext if bIsInterfaceContext
        //is set on function call statement. We need to handle it here, otherwise information will be lost
        if (ContextObject->GetStringField(TEXT("Inst")) == TEXT("InterfaceContext")) {
            bIsInterfaceContext = true;
            ContextObject = ContextObject->GetObjectField(TEXT("Expression"));
        }
        
        Context = ProcessExpression(ContextObject);
        if (!Context.IsValid()) return nullptr;   // context object degraded (call-on-call result / unresolved const) — don't deref null
        Context->ContextType = bIsClassContext ? FKismetTerminal::EContextType_Class : FKismetTerminal::EContextType_Object;
        Statement = Statement->GetObjectField(TEXT("Expression"));
    }
    
    if (!Statement.IsValid()) return nullptr;
    const FString InstructionName = Statement->GetStringField(TEXT("Inst"));

    //A Context can also wrap a NON-call inner expression (e.g. a member-variable read) → degrade, don't crash.
    if (!IsCallFunctionInstruction(InstructionName)) return nullptr;

    TSharedPtr<FKismetCompiledStatement> Result = MakeShareable(new FKismetCompiledStatement());
    Result->Type = ECompiledStatementType::KCST_CallFunction;
    Result->FunctionContext = Context;
    Result->bIsInterfaceContext = bIsInterfaceContext;

    //Resolve UFunction object by name and provided context
    const FString FunctionName = Statement->GetStringField(TEXT("Function"));
    Result->FunctionName = FName(*FunctionName);   // keep the original name so a reinstanced FunctionToCall can be re-resolved on the live class

    //Resolve context class for querying function by name
    UClass* ContextObjectClass;

    if (InstructionName != TEXT("CallMath")) {
        //All function calls will have proper context object set, and it will be either an object or class
        //Either way, PSC_Self handling is equal for both of these cases, and resulting class will be
        //class of the object on which function will be called (for static functions, it will be class CDO)

        //Resolve Context class. Most calls carry a Context (object or class), but implicit-self calls
        //(LocalVirtualFunction / LocalFinalFunction) carry NO Context expression at all, so Context is invalid
        //here — treat that (and an explicit Self) as the owner (skeleton generated) class.
        if (!Context.IsValid() || Context->Type.PinSubCategory == UEdGraphSchema_K2::PSC_Self) {
            ContextObjectClass = OwnerBlueprint->SkeletonGeneratedClass;
        } else {
            ContextObjectClass = Cast<UClass>(Context->Type.PinSubCategoryObject);
        }
    } else {
        //CallMath is special - it does not have any kind of context, so to resolve
        //function we have to look up context class recorded in instruction data
        const FString ContextClassPath = Statement->GetStringField(TEXT("ContextClass"));
        ContextObjectClass = LoadObject<UClass>(NULL, *ContextClassPath);
    }

    //Soft-degrade (return an invalid statement the driver skips) instead of check()-crashing on any unresolved
    //call — the F3 sweep decompiles arbitrary cooked bytecode, so this must never crash the editor.
    UFunction* ResolvedFunction = ContextObjectClass ? ContextObjectClass->FindFunctionByName(*FunctionName) : nullptr;
    if (!ResolvedFunction) {
        return nullptr;
    }

    if (InstructionName == TEXT("LocalVirtualFunction") || InstructionName == TEXT("VirtualFunction")) {
        //Obviously it is not a parent context for a virtual function
        Result->FunctionToCall = ResolvedFunction;
        Result->bIsParentContext = false;
        
    } else if (InstructionName == TEXT("LocalFinalFunction") || InstructionName == TEXT("FinalFunction")) {
        //Final function call, possibly in the parent context
        //We set parent context flag if function in question is not final, but is called with FinalFunction opcode
        Result->FunctionToCall = ResolvedFunction;
        Result->bIsParentContext = !ResolvedFunction->HasAnyFunctionFlags(EFunctionFlags::FUNC_Final);
        
    } else if (InstructionName == TEXT("CallMath")) {
        Result->FunctionToCall = ResolvedFunction;
        Result->bIsParentContext = false;
        
    } else {
        //Unhandled call opcode: degrade the statement (the driver skips a null) instead of taking the editor down
        //mid-sweep. Currently unreachable-by-construction (the IsCallFunctionInstruction guard above admits exactly
        //the five opcodes handled here) — but that coupling is invisible from here, so a new opcode added to the
        //predicate must NOT turn into a fatal. Same catch-all shape as ProcessStatement/ProcessLiteralExpression.
        UE_LOG(LogTemp, Warning, TEXT("[MifKR] Unhandled function call opcode (deferred): %s"), *InstructionName);
        return nullptr;
    }

    //Do argument processing that is common for all function call instructions
    TArray<TSharedPtr<FJsonValue>> Parameters = Statement->GetArrayField(TEXT("Parameters"));

    int32 NumParams = 0;
    int32 LatentInfoParameterIndex = -1;
    
    for (TFieldIterator<FProperty> PropIt(Result->FunctionToCall); PropIt && (PropIt->PropertyFlags & CPF_Parm); ++PropIt) {
        FProperty* FuncParamProperty = *PropIt;

        //Skip return values because they are handled in a special way when we happened to be an expression in EX_Let statement
        if (!FuncParamProperty->HasAnyPropertyFlags(CPF_ReturnParm)) {
            
            //Record LatentInfo parameter which we will resolve later
            if (FuncParamProperty->GetName() == Result->FunctionToCall->GetMetaData("LatentInfo")) {
                LatentInfoParameterIndex = NumParams;
            }
            
            if (!Parameters.IsValidIndex(NumParams)) return nullptr;   // signature/JSON param-count mismatch → degrade
            const TSharedPtr<FJsonObject> ParameterExpression = Parameters[NumParams++]->AsObject();
            TSharedPtr<FKismetTerminal> ParameterTerminal = ProcessFunctionParameter(ParameterExpression);

            Result->RHS.Add(ParameterTerminal);
        }
    }

    //Detect calls into ubergraph. They need special handling because first parameter
    //Is the offset to jump on to start execution of the given event this function is the stub for,
    //and since we do not really expose offsets in compiled statement representation, we need to find
    //compiled statement inside of the ubergraph object and set is as target for this statement
    if (FunctionName == ExecuteUbergraphFunctionName) {
        //Call into the ubergraph (event dispatch). Resolve the target statement if we can; otherwise leave it
        //unresolved (graph degrades) rather than crash. Events are outside MVP scope anyway.
        const int32 OffsetIntoUbergraph = (Result->RHS.Num() > 0 && Result->RHS[0].IsValid())
            ? FCString::Atoi(*Result->RHS[0]->StringLiteral) : -1;
        const TSharedPtr<FKismetCompiledStatement>* Found = (UberGraphTransformer.IsValid() && !IsUberGraphFunction())
            ? UberGraphTransformer->StatementsByOffset.Find(OffsetIntoUbergraph) : nullptr;
        if (Found) {
            Result->TargetLabel = *Found;
            Result->bIsCallIntoUbergraph = true;
        }
    }

    //Detect latent function calls that have next statement index to execute in this function
    //After completing async operation inside of the LatentInfo structure parameter. We need to extract it and set as TargetLabel
    //Latent actions normally only appear in the ubergraph; on real cooked bytecode a LatentInfo-tagged param can
    //show up elsewhere too, so guard every assumption and simply skip the resume patch-up when it doesn't apply.
    // Recognize the ubergraph by NAME PREFIX, not IsUberGraphFunction(): the latter builds the expected name from the
    // COPY blueprint's name (ExecuteUbergraph_<Copy>) but the event-reconstruction path transforms the COOKED SOURCE
    // ubergraph, so it never matched and the latent resume edge was silently dropped. Any ExecuteUbergraph_* function
    // IS an ubergraph; the resume still only fires when LatentActionInfo.ExecutionFunction == CurrentFunctionName (below).
    if (LatentInfoParameterIndex != -1 && CurrentFunctionName.StartsWith(TEXT("ExecuteUbergraph")) && Result->RHS.IsValidIndex(LatentInfoParameterIndex)
        && Result->RHS[LatentInfoParameterIndex].IsValid()) {
        UScriptStruct* LatentActionInfoStruct = FLatentActionInfo::StaticStruct();
        const TSharedPtr<FKismetTerminal> LatentInfoTerminal = Result->RHS[LatentInfoParameterIndex];

        //Export textual representation of latent action info into the proper struct
        FLatentActionInfo LatentActionInfo;
        LatentActionInfoStruct->ImportText(*LatentInfoTerminal->StringLiteral, &LatentActionInfo, NULL, 0, GError, TEXT("LatentActionInfo"));

        //Only schedule the resume patch-up when the latent action targets THIS function (the normal case).
        if (LatentActionInfo.ExecutionFunction.ToString() == CurrentFunctionName) {
            const int32 ResumeOffsetInUberGraph = LatentActionInfo.Linkage;
            this->JumpPatchUpTable.Add(Result, ResumeOffsetInUberGraph);
            Result->bIsCallIntoUbergraph = false;
        }
    }
    
    return Result;
}

TSharedPtr<FKismetTerminal> FKismetBytecodeTransformer::ProcessFunctionParameter(TSharedPtr<FJsonObject> ParameterExpression) {
    const FString ParameterInstructionName = ParameterExpression->GetStringField(TEXT("Inst"));

    TSharedPtr<FKismetTerminal> ParameterTerminal;

    //Functions can have statements passed as parameters inline sometimes,
    //so we need to handle this gracefully here, because ProcessExpression has no idea how to deal with statements
            
    //GetArrayItem is one of the only 3 statements that can appear as function arguments. Noticeably, ArrayGetByRef
    //will actually never appear as a dedicated statement outside of inlined generated parameter context
    if (ParameterInstructionName == TEXT("ArrayGetByRef")) {
        TSharedPtr<FKismetCompiledStatement> ArrayItemStatement = MakeShareable(new FKismetCompiledStatement());
        ArrayItemStatement->Type = ECompiledStatementType::KCST_ArrayGetByRef;
        TSharedPtr<FKismetTerminal> ArrayExpression = ProcessExpression(ParameterExpression->GetObjectField(TEXT("ArrayExpression")));
        ArrayItemStatement->RHS.Add(ArrayExpression);
        ArrayItemStatement->RHS.Add(ProcessExpression(ParameterExpression->GetObjectField(TEXT("IndexExpression"))));

        //Inner element type is basically the same as an array expression type, but container type is None and it is always a reference
        //because corresponding byte code sets MostRecentProperty/PropertyValue as well as RESULT_PARAM.
        //Degrade if the array operand didn't reconstruct as an Array-container pin (inlined/unresolved call operand,
        //or an unresolved import → bad_type/None): don't deref null or check()-crash the editor mid-sweep.
        if (!ArrayExpression.IsValid() || ArrayExpression->Type.ContainerType != EPinContainerType::Array) {
            return MakeShareable(new FKismetTerminal());   // placeholder keeps the non-null postcondition at function end
        }
        FEdGraphPinType InnerElementType = ArrayExpression->Type;
        InnerElementType.ContainerType = EPinContainerType::None;
        InnerElementType.bIsReference = true;
        
        ParameterTerminal = MakeShareable(new FKismetTerminal());
        ParameterTerminal->Type = InnerElementType;
        ParameterTerminal->InlineGeneratedParameter = ArrayItemStatement;
    }

    //Select is also the other node that will never appear on it's own as a dedicated statement,
    //because actually it is a perfectly pure node just returning value depending on the inputs
    else if (ParameterInstructionName == TEXT("SwitchValue")) {
        TSharedPtr<FKismetCompiledStatement> SwitchValue = MakeShareable(new FKismetCompiledStatement());
        SwitchValue->Type = ECompiledStatementType::KCST_SwitchValue;
        //First RHS terminal is an index
        SwitchValue->RHS.Add(ProcessExpression(ParameterExpression->GetObjectField(TEXT("Expression"))));

        //Record value type of the first case, it will be the type of entire case statement as well, falling back to default statement
        //Technically it is incorrect because cases can return more specific types than the base type,
        //but we are okay about it, since types are really only used for property/function resolution, which will work for more specific types
        TSharedPtr<FKismetTerminal> FirstValueTerminal;
        
        //Append pairs of (case value, case result) cases in order
        TArray<TSharedPtr<FJsonValue>> Cases = ParameterExpression->GetArrayField(TEXT("Cases"));
        for (const TSharedPtr<FJsonValue>& CaseValue : Cases) {
            TSharedPtr<FJsonObject> CasePairObject = CaseValue->AsObject();
            TSharedPtr<FKismetTerminal> CaseTestValue = ProcessExpression(CasePairObject->GetObjectField(TEXT("CaseValue")));
            TSharedPtr<FKismetTerminal> CaseResult = ProcessExpression(CasePairObject->GetObjectField(TEXT("CaseResult")));
            if (!CaseTestValue.IsValid()) return MakeShareable(new FKismetTerminal());   // case-test value unresolved → degrade Select to placeholder, don't check()-crash
            
            if (!FirstValueTerminal.IsValid()) {
                FirstValueTerminal = CaseResult;
            }
            
            //Case test values should *always* be literals, because so far only node currently generating KCST_SwitchValue is Select,
            //and select allows selecting between literals by passed value only.
            //ProcessExpression can hand back a NON-literal here on real cooked bytecode (a variable/context terminal),
            //so this is reachable — degrade the Select to a placeholder exactly like the unresolved-case-test path
            //above rather than check()-crash the sweep.
            if (!CaseTestValue->bIsLiteral) {
                UE_LOG(LogTemp, Warning, TEXT("[MifKR] SwitchValue case test is not a literal (deferred)"));
                return MakeShareable(new FKismetTerminal());
            }
                    
            SwitchValue->RHS.Add(CaseTestValue);
            SwitchValue->RHS.Add(CaseResult);
        }

        //Default value is appended at the end
        TSharedPtr<FKismetTerminal> DefaultValue = ProcessExpression(ParameterExpression->GetObjectField(TEXT("DefaultResult")));
        SwitchValue->RHS.Add(DefaultValue);

        if (!FirstValueTerminal.IsValid()) {
            FirstValueTerminal = DefaultValue;
        }
        if (!FirstValueTerminal.IsValid()) {
            return MakeShareable(new FKismetTerminal());   // all Select case results + default degraded (cooked-only refs) → placeholder, don't deref null
        }

        ParameterTerminal = MakeShareable(new FKismetTerminal());
        ParameterTerminal->Type = FirstValueTerminal->Type;
        ParameterTerminal->InlineGeneratedParameter = SwitchValue;
    }

    //Function calls can be inlined too, but as far as I am aware, this is only used for MathExpression node
    //I must admit though, that these are MUCH more powerful than most users think -
    //they can not only use standard mathematical operators and functions, but also ANY
    //static, pure, native final functions exposed by blueprint libraries
    //These functions, obviously, cannot have any context though.
    //They, in fact, will be called with a context object that is logically wrong,
    //but it still works, because native static functions don't use context object at all.
    else if (IsCallFunctionInstruction(ParameterInstructionName)) {
        TSharedPtr<FKismetCompiledStatement> InlineFunctionCall = ProcessFunctionCallStatement(ParameterExpression);
        //Soft-degrade an unresolved inline call (ProcessFunctionCallStatement now returns null on failure) into a
        //placeholder terminal so the OUTER statement degrades gracefully instead of crashing the editor.
        FProperty* ReturnProperty = (InlineFunctionCall.IsValid() && InlineFunctionCall->FunctionToCall)
            ? InlineFunctionCall->FunctionToCall->GetReturnProperty() : nullptr;
        if (!ReturnProperty) {
            return MakeShareable(new FKismetTerminal());
        }
        ParameterTerminal = MakeShareable(new FKismetTerminal());
        FPropertyTypeHelper::ConvertPropertyToPinType(ReturnProperty, ParameterTerminal->Type);
        ParameterTerminal->InlineGeneratedParameter = InlineFunctionCall;
    }
    else {
        //Otherwise it is a simple expression that we need to parse
        ParameterTerminal = ProcessExpression(ParameterExpression);
    }

    if (!ParameterTerminal.IsValid()) {
        // A parameter sub-expression degraded to null (unresolved const/inlined call arg). Return a placeholder
        // terminal so the outer call statement survives and downstream RHS handling degrades, not crashes.
        return MakeShareable(new FKismetTerminal());
    }
    return ParameterTerminal;
}
