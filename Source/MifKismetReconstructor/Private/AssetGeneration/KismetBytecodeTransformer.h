#pragma once
#include "CoreMinimal.h"
#include "AssetGeneration/KismetIntermediateFormat.h"
#include "Json.h"

/**
 * Handles transformation of kismet bytecode into the intermediate format
 * To aid with decompilation and represent bytecode in a format closer to the source text
 */
class FKismetBytecodeTransformer {
public:
    /** Blueprint should have a valid skeleton class generated for the resolution of EX_Self and referenced functions.
        InSourceClass = the COOKED class the bytecode was disassembled FROM (i.e. the disassembler's SelfScope,
        SourceFunc->GetTypedOuter<UClass>()) — pin TYPES must round-trip their "<SELF>" token back to THAT class.
        No default argument on purpose: every caller must state which class the bytecode came from. See GetTypeSelfScope. */
    FKismetBytecodeTransformer(UBlueprint* Blueprint, UClass* InSourceClass);

    /** Sets transformer to look up instruction by offset inside of the uber graph */
    void SetUberGraphTransformer(TSharedPtr<FKismetBytecodeTransformer> Transformer);

    /** Begins statement generation by populating transformer with serialized bytecode */
    void SetSourceStatements(const FString& FunctionName, const TArray<TSharedPtr<FJsonObject>>& Statements);

    /** Finishes generation and returns result statements */
    TArray<TSharedPtr<FKismetCompiledStatement>> FinishGeneration();

    /** Returns true if we are currently processing ubergraph function */
    FORCEINLINE bool IsUberGraphFunction() const { return CurrentFunctionName == ExecuteUbergraphFunctionName; } 
private:
    /** Class path of the class this bytecode belongs to. Should exist and be populated with function stubs */
    UBlueprint* OwnerBlueprint;
    /** The COOKED class this bytecode was disassembled from (the disassembler's SelfScope). Pin types serialize refs to
        it as the "<SELF>" token, so they must deserialize back to IT — not to the copy's skeleton. */
    UClass* SourceClass = nullptr;

    /** Self-scope for deserializing pin TYPES only: the source class the "<SELF>" token was written against.
        EX_Self and self-CONTEXT resolution deliberately keep using OwnerBlueprint->SkeletonGeneratedClass. */
    UClass* GetTypeSelfScope() const;
    /** Name of the ExecuteUbergraph function associated with the current blueprint. It is used to determine whenever function is the ubergraph call */
    FString ExecuteUbergraphFunctionName;
    /** Transformer used to parse ubergraph code, used to resolve references into ubergraph */
    TSharedPtr<FKismetBytecodeTransformer> UberGraphTransformer;
    /** Name of the function we are currently transforming */
    FString CurrentFunctionName;

    static bool IsContextInstruction(const FString& InstructionName);
    static bool IsCallFunctionInstruction(const FString& InstructionName);
    static bool IsVariableInstruction(const FString& InstructionName);
    
    TSharedPtr<FKismetCompiledStatement> ProcessStatement(TSharedPtr<FJsonObject> Statement);
    TSharedPtr<FKismetTerminal> ProcessExpression(TSharedPtr<FJsonObject> Expression);
    TSharedPtr<FKismetTerminal> ProcessLiteralExpression(TSharedPtr<FJsonObject> Expression, bool bIsDelimited);
    TSharedPtr<FKismetCompiledStatement> ProcessFunctionCallStatement(TSharedPtr<FJsonObject> Statement);
    TSharedPtr<FKismetTerminal> ProcessFunctionParameter(TSharedPtr<FJsonObject> Expression);

    TMap<int32, TSharedPtr<FKismetCompiledStatement>> StatementsByOffset;
    TArray<TSharedPtr<FKismetCompiledStatement>> ResultStatements;

    //Map of patch-ups to apply to target labels after all expressions have been parsed
    //It will convert int32 offsets in bytecode to absolute statement references
    //It might also end up converting statement type if referenced statement is happens to be Return
    //then jump is converted to KCST_GotoReturn
    TMap<TSharedPtr<FKismetCompiledStatement>, int32> JumpPatchUpTable;

};
