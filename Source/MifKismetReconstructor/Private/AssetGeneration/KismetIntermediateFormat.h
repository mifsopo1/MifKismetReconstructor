#pragma once
#include "CoreMinimal.h"
#include "EdGraph/EdGraphPin.h"

// Ported from UEAssetToolkit-Fixes (AssetGenerator) → the MifKismetReconstructor plugin.
// The compiler-mirrored intermediate representation the transformer emits and the decompiler consumes.
//
// STEP-1 CHANGE (the design's gating prerequisite): FKismetTerminal::operator== and GetTypeHash were
// `checkf(0, "implement later")` stubs — every terminal-keyed map (.Add/.Find) would have asserted.
// They are implemented below with VALUE semantics so the same logical variable reference, represented by
// distinct TSharedPtr instances across statements, compares/hashes equal (required to wire a producer's
// output pin to every later read of that variable).

/** Basically mimics EKismetCompiledStatementType in the KismetCompiler module */
enum class ECompiledStatementType : uint8 {
	KCST_Nop,
	// [wiring =] TargetObject->FunctionToCall(wiring)
	KCST_CallFunction,
	// TargetObject->TargetProperty = [wiring]
	KCST_Assignment,
	// goto TargetLabel
	KCST_UnconditionalGoto,
	// FlowStack.Push(TargetLabel)
	KCST_PushState,
	// [if (!TargetObject->TargetProperty)] goto TargetLabel
	KCST_GotoIfNot,
	// return TargetObject->TargetProperty
	KCST_Return,
	// if (FlowStack.Num()) { NextState = FlowStack.Pop; } else { return; }
	KCST_EndOfThread,
	// NextState = LHS;
	KCST_ComputedGoto,
	// [if (!TargetObject->TargetProperty)] { same as KCST_EndOfThread; }
	KCST_EndOfThreadIfNot,
	// TargetInterface(TargetObject)
	KCST_CastObjToInterface,
	// Cast<TargetClass>(TargetObject)
	KCST_DynamicCast,
	// (TargetObject != None)
	KCST_ObjectToBool,
	// TargetDelegate->Add(EventDelegate)
	KCST_AddMulticastDelegate,
	// TargetDelegate->Clear()
	KCST_ClearMulticastDelegate,
	// Creates simple delegate
	KCST_BindDelegate,
	// TargetDelegate->Remove(EventDelegate)
	KCST_RemoveMulticastDelegate,
	// TargetDelegate->Broadcast(...)
	KCST_CallDelegate,
	// Creates and sets an array literal term
	KCST_CreateArray,
	// TargetInterface(Interface)
	KCST_CrossInterfaceCast,
	// Cast<TargetClass>(TargetObject)
	KCST_MetaCast,
	KCST_AssignmentOnPersistentFrame,
	// Cast<TargetClass>(TargetInterface)
	KCST_CastInterfaceToObj,
	// goto ReturnLabel
	KCST_GotoReturn,
	// [if (!TargetObject->TargetProperty)] goto TargetLabel
	KCST_GotoReturnIfNot,
	KCST_SwitchValue, //Can only appear as the InlineGeneratedParameter in FKismetTerminal
	KCST_ArrayGetByRef, //Can only appear as the InlineGeneratedParameter in FKismetTerminal
	KCST_CreateSet,
	KCST_CreateMap,
};

struct FKismetCompiledStatement {

	FORCEINLINE FKismetCompiledStatement()
		: Type(ECompiledStatementType::KCST_Nop)
		, FunctionContext(NULL)
		, FunctionToCall(NULL)
		, TargetLabel(NULL)
		, UbergraphCallIndex(-1)
		, LHS(NULL)
		, bIsInterfaceContext(false)
		, bIsParentContext(false)
		, bIsCallIntoUbergraph(false)
	{}

	ECompiledStatementType Type;

	// Object that the function should be called on, or NULL to indicate self (KCST_CallFunction)
	TSharedPtr<struct FKismetTerminal> FunctionContext;

	// Function that executes the statement (KCST_CallFunction)
	UFunction* FunctionToCall;

	// The ORIGINAL resolved name of FunctionToCall (KCST_CallFunction). Kept so a stale/reinstanced FunctionToCall
	// can be re-resolved by name on the live class (a reinstanced UFunction*'s object name gains a _N suffix).
	FName FunctionName;

	// Target label (KCST_Goto, or KCST_CallFunction that requires an ubergraph reference)
	TSharedPtr<FKismetCompiledStatement> TargetLabel;

	// The index of the argument to replace (only used when KCST_CallFunction has a non-NULL TargetLabel)
	int32 UbergraphCallIndex;

	// Destination of assignment statement or result from function call
	TSharedPtr<struct FKismetTerminal> LHS;

	// Argument list of function call or source of assignment statement
	TArray<TSharedPtr<struct FKismetTerminal>> RHS;

	// Is this node an interface context? (KCST_CallFunction)
	bool bIsInterfaceContext;

	// Is this function called on a parent class (super, etc)?  (KCST_CallFunction)
	bool bIsParentContext;

	// True if this function call is actually a call into ubergraph, and TargetLabel will belong to the ubergraph
	bool bIsCallIntoUbergraph;
};

/** A terminal in the graph (literal or variable reference) */
struct FKismetTerminal {

	FEdGraphPinType Type;
	bool bIsLiteral;

	// Context->
	TSharedPtr<FKismetTerminal> Context;

	/** Literal value represented as the string */
	FString StringLiteral;

	// For non-literal terms, this is the property being referenced (name only — locals aren't reconstructed as UProperty)
	FString AssociatedVarProperty;

	/** Pointer to an object literal */
	UObject* ObjectLiteral;

	/** The FText literal */
	FText TextLiteral;

	/**
	 * Reference to the statement passed inline as the function parameter (GetArrayItem / Select / MathExpression).
	 * Allows statement execution where only expressions are allowed.
	 */
	TSharedPtr<FKismetCompiledStatement> InlineGeneratedParameter;

	FORCEINLINE FKismetTerminal()
		: bIsLiteral(false)
		, Context(nullptr)
		, AssociatedVarProperty(TEXT(""))
		, ObjectLiteral(nullptr)
		, VarType(EVarType_Instanced)
		, ContextType(EContextType_Object)
	{}

	enum EVarType {
		EVarType_Local,
		EVarType_Default,
		EVarType_Instanced
	};

	// For non-literal terms, this is set to the type of variable reference
	EVarType VarType;

	// Context types (mutually-exclusive)
	enum EContextType {
		EContextType_Class,
		EContextType_Struct,
		EContextType_Object,
	};

	// If this term is also a context, this indicates which type of context it is
	EContextType ContextType;

	// Value-semantics equality: same literal value, OR same variable reference in the same context.
	// Depth-bounded so a pathological context chain cannot recurse unboundedly.
	bool EqualsWithDepth(const FKismetTerminal& O, int32 Depth) const {
		if (Depth > 32) return true; // guard: treat very deep chains as equal at the tail
		if (bIsLiteral != O.bIsLiteral) return false;
		if (!(Type == O.Type)) return false;
		if (bIsLiteral) {
			return StringLiteral == O.StringLiteral
				&& ObjectLiteral == O.ObjectLiteral
				&& TextLiteral.ToString() == O.TextLiteral.ToString();
		}
		if (VarType != O.VarType) return false;
		if (ContextType != O.ContextType) return false;
		if (AssociatedVarProperty != O.AssociatedVarProperty) return false;
		if (Context.IsValid() != O.Context.IsValid()) return false;
		if (Context.IsValid() && !Context->EqualsWithDepth(*O.Context, Depth + 1)) return false;
		return true;
	}

	FORCEINLINE bool operator==(const FKismetTerminal& O) const {
		return EqualsWithDepth(O, 0);
	}

	uint32 HashWithDepth(int32 Depth) const {
		uint32 H = bIsLiteral ? 0x9E3779B9u : 0u;
		H = HashCombine(H, GetTypeHash(Type.PinCategory));
		H = HashCombine(H, GetTypeHash(Type.PinSubCategory));
		H = HashCombine(H, PointerHash(Type.PinSubCategoryObject.Get()));
		H = HashCombine(H, (uint32) Type.ContainerType);
		if (bIsLiteral) {
			H = HashCombine(H, GetTypeHash(StringLiteral));
			H = HashCombine(H, PointerHash(ObjectLiteral));
			H = HashCombine(H, GetTypeHash(TextLiteral.ToString()));
		} else {
			H = HashCombine(H, (uint32) VarType);
			H = HashCombine(H, (uint32) ContextType);
			H = HashCombine(H, GetTypeHash(AssociatedVarProperty));
			if (Context.IsValid() && Depth <= 32) {
				H = HashCombine(H, Context->HashWithDepth(Depth + 1));
			}
		}
		return H;
	}
};

FORCEINLINE uint32 GetTypeHash(const FKismetTerminal& Terminal) {
	return Terminal.HashWithDepth(0);
}
