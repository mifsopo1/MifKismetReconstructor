#include "Toolkit/KismetBytecodeDisassemblerJson.h"
#include "Toolkit/PropertyTypeHelper.h"
#include "Dom/JsonValue.h"
#include "UObject/Class.h"
#include "UObject/UnrealType.h"
#include "UObject/Script.h"

// Ported from UEAssetToolkit-Fixes (AssetDumper) → UE5.3.2 and hardened for the cooked-editor fork.
// Changes vs the UE4 original:
//   * EX_PrimitiveCast → EX_Cast (0x38); reads only [byte kind][expr] (no extra pointer, no checkf).
//   * LWC widths: EX_VectorConst / EX_RotationConst / EX_TransformConst read 8-byte components.
//   * New UE5.3 opcodes: DoubleConst, Vector3fConst, BitFieldConst, Skip, NothingInt32,
//     PropertyConst, ClassSparseDataVariable, AutoRtfmTransact / StopTransact / AbortIfNot.
//   * Every fatal checkf(0)/check → record-and-abort (unknown operand length ⇒ cannot continue).
//   * Every raw bytecode pointer deref is null-guarded; every low-level read is bounds-guarded.
//   * Per-opcode histogram for the Phase-0 spike.

TSharedPtr<FJsonObject> FKismetBytecodeDisassemblerJson::MakeUnknownNode(uint8 Opcode, int32 AtIndex) {
	bDisassemblyFailed = true;
	FailedOpcode = Opcode;
	FailedAtIndex = AtIndex;
	TSharedPtr<FJsonObject> R = MakeShareable(new FJsonObject());
	R->SetStringField(TEXT("Inst"), TEXT("Unknown"));
	R->SetNumberField(TEXT("Op"), Opcode);
	R->SetNumberField(TEXT("AtIndex"), AtIndex);
	return R;
}

FString FKismetBytecodeDisassemblerJson::SafePathName(const UObject* Object) {
	return Object ? Object->GetPathName() : FString(TEXT("<unresolved>"));
}

TSharedPtr<FJsonObject> FKismetBytecodeDisassemblerJson::SerializeExpression(int32& ScriptIndex) {
	const int32 OpcodeIndex = ScriptIndex;
	const EExprToken Opcode = (EExprToken) ReadByte(ScriptIndex);
	if (bDisassemblyFailed) {
		return MakeUnknownNode((uint8) Opcode, OpcodeIndex);
	}
	OpcodeHistogram.FindOrAdd((uint8) Opcode)++;

	TSharedPtr<FJsonObject> Result = MakeShareable(new FJsonObject());

	switch (Opcode) {
		case EX_Cast:
		{
			// A type conversion. UE5: [uint8 kind][expr]. Kept as "PrimitiveCast" for transformer compatibility.
			Result->SetStringField(TEXT("Inst"), TEXT("PrimitiveCast"));
			const uint8 ConversionType = ReadByte(ScriptIndex);
			if (ConversionType == ECastToken::CST_InterfaceToBool) {
				Result->SetStringField(TEXT("CastType"), TEXT("InterfaceToBool"));
			} else if (ConversionType == ECastToken::CST_ObjectToBool) {
				Result->SetStringField(TEXT("CastType"), TEXT("ObjectToBool"));
			} else {
				Result->SetStringField(TEXT("CastType"), FString::FromInt(ConversionType));
			}
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_SetSet:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("SetSet"));
			Result->SetObjectField(TEXT("LeftSideExpression"), SerializeExpression(ScriptIndex));

			TArray<TSharedPtr<FJsonValue>> Values;
			ReadInt(ScriptIndex); //Skip element amount
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex) && Script[ScriptIndex] != EX_EndSet) {
				Values.Add(MakeShareable(new FJsonValueObject(SerializeExpression(ScriptIndex))));
			}
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip EX_EndSet
			Result->SetArrayField(TEXT("Values"), Values);
			break;
		}
		case EX_SetConst:
		{
			FProperty* InnerProp = ReadPointer<FProperty>(ScriptIndex);
			FEdGraphPinType PropertyPinType;
			FPropertyTypeHelper::ConvertPropertyToPinType(InnerProp, PropertyPinType);

			Result->SetStringField(TEXT("Inst"), TEXT("SetConst"));
			Result->SetObjectField(TEXT("InnerProperty"), FPropertyTypeHelper::SerializeGraphPinType(PropertyPinType, SelfScope.Get()));

			TArray<TSharedPtr<FJsonValue>> Values;
			ReadInt(ScriptIndex); //Skip element amount
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex) && Script[ScriptIndex] != EX_EndSetConst) {
				Values.Add(MakeShareable(new FJsonValueObject(SerializeExpression(ScriptIndex))));
			}
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip EX_EndSetConst
			Result->SetArrayField(TEXT("Values"), Values);
			break;
		}
		case EX_SetMap:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("SetMap"));
			Result->SetObjectField(TEXT("LeftSideExpression"), SerializeExpression(ScriptIndex));

			TArray<TSharedPtr<FJsonValue>> Values;
			ReadInt(ScriptIndex); //Skip element amount
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex) && Script[ScriptIndex] != EX_EndMap) {
				TSharedPtr<FJsonObject> KeyExpression = SerializeExpression(ScriptIndex);
				TSharedPtr<FJsonObject> ValueExpression = SerializeExpression(ScriptIndex);
				TSharedRef<FJsonObject> Pair = MakeShareable(new FJsonObject());
				Pair->SetObjectField(TEXT("Key"), KeyExpression);
				Pair->SetObjectField(TEXT("Value"), ValueExpression);
				Values.Add(MakeShareable(new FJsonValueObject(Pair)));
			}
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip EX_EndMap
			Result->SetArrayField(TEXT("Values"), Values);
			break;
		}
		case EX_MapConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("MapConst"));

			FProperty* KeyProp = ReadPointer<FProperty>(ScriptIndex);
			FEdGraphPinType KeyPropPinType;
			FPropertyTypeHelper::ConvertPropertyToPinType(KeyProp, KeyPropPinType);
			Result->SetObjectField(TEXT("KeyProperty"), FPropertyTypeHelper::SerializeGraphPinType(KeyPropPinType, SelfScope.Get()));

			FProperty* ValProp = ReadPointer<FProperty>(ScriptIndex);
			FEdGraphPinType ValuePropPinType;
			FPropertyTypeHelper::ConvertPropertyToPinType(ValProp, ValuePropPinType);
			Result->SetObjectField(TEXT("ValueProperty"), FPropertyTypeHelper::SerializeGraphPinType(ValuePropPinType, SelfScope.Get()));

			TArray<TSharedPtr<FJsonValue>> Values;
			ReadInt(ScriptIndex); //Skip element amount
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex) && Script[ScriptIndex] != EX_EndMapConst) {
				TSharedPtr<FJsonObject> KeyExpression = SerializeExpression(ScriptIndex);
				TSharedPtr<FJsonObject> ValueExpression = SerializeExpression(ScriptIndex);
				TSharedRef<FJsonObject> Pair = MakeShareable(new FJsonObject());
				Pair->SetObjectField(TEXT("Key"), KeyExpression);
				Pair->SetObjectField(TEXT("Value"), ValueExpression);
				Values.Add(MakeShareable(new FJsonValueObject(Pair)));
			}
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip EX_EndMapConst
			Result->SetArrayField(TEXT("Values"), Values);
			break;
		}
		case EX_ObjToInterfaceCast:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("ObjToInterfaceCast"));
			UClass* InterfaceClass = ReadPointer<UClass>(ScriptIndex);
			Result->SetStringField(TEXT("InterfaceClass"), SafePathName(InterfaceClass));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_CrossInterfaceCast:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("CrossInterfaceCast"));
			UClass* InterfaceClass = ReadPointer<UClass>(ScriptIndex);
			Result->SetStringField(TEXT("InterfaceClass"), SafePathName(InterfaceClass));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_InterfaceToObjCast:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("InterfaceToObjCast"));
			UClass* ObjectClass = ReadPointer<UClass>(ScriptIndex);
			Result->SetStringField(TEXT("ObjectClass"), SafePathName(ObjectClass));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_Let:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("Let"));
			ReadPointer<FProperty>(ScriptIndex); //Skip property pointer, type deducible from Variable
			Result->SetObjectField(TEXT("Variable"), SerializeExpression(ScriptIndex));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_LetObj:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("LetObj"));
			Result->SetObjectField(TEXT("Variable"), SerializeExpression(ScriptIndex));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_LetWeakObjPtr:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("LetWeakObjPtr"));
			Result->SetObjectField(TEXT("Variable"), SerializeExpression(ScriptIndex));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_LetBool:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("LetBool"));
			Result->SetObjectField(TEXT("Variable"), SerializeExpression(ScriptIndex));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_LetValueOnPersistentFrame:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("LetValueOnPersistentFrame"));
			FProperty* Property = ReadPointer<FProperty>(ScriptIndex);
			Result->SetStringField(TEXT("PropertyName"), Property ? Property->GetName() : FString(TEXT("<unresolved>")));

			FEdGraphPinType PropertyType;
			FPropertyTypeHelper::ConvertPropertyToPinType(Property, PropertyType);
			Result->SetObjectField(TEXT("PropertyType"), FPropertyTypeHelper::SerializeGraphPinType(PropertyType, SelfScope.Get()));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_StructMemberContext:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("StructMemberContext"));
			FProperty* Property = ReadPointer<FProperty>(ScriptIndex);
			FEdGraphPinType PropertyPinType;
			FPropertyTypeHelper::ConvertPropertyToPinType(Property, PropertyPinType);
			Result->SetObjectField(TEXT("PropertyType"), FPropertyTypeHelper::SerializeGraphPinType(PropertyPinType, SelfScope.Get()));
			Result->SetStringField(TEXT("PropertyName"), Property ? Property->GetName() : FString(TEXT("<unresolved>")));
			Result->SetObjectField(TEXT("StructExpression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_LetDelegate:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("LetDelegate"));
			Result->SetObjectField(TEXT("Variable"), SerializeExpression(ScriptIndex));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_LocalVirtualFunction:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("LocalVirtualFunction"));
			// Name-based virtual self-call. Emit under "Function" (same key VirtualFunction uses) so the
			// transformer's ProcessFunctionCallStatement resolves it — NOT "FunctionName" (which it never reads).
			Result->SetStringField(TEXT("Function"), ReadName(ScriptIndex));
			TArray<TSharedPtr<FJsonValue>> Parameters;
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex) && Script[ScriptIndex] != EX_EndFunctionParms) {
				Parameters.Add(MakeShareable(new FJsonValueObject(SerializeExpression(ScriptIndex))));
			}
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip EX_EndFunctionParms
			Result->SetArrayField(TEXT("Parameters"), Parameters);
			break;
		}
		case EX_LocalFinalFunction:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("LocalFinalFunction"));
			UFunction* StackNode = ReadPointer<UFunction>(ScriptIndex);
			Result->SetStringField(TEXT("Function"), StackNode ? StackNode->GetName() : FString(TEXT("<unresolved>")));
			TArray<TSharedPtr<FJsonValue>> Parameters;
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex) && Script[ScriptIndex] != EX_EndFunctionParms) {
				Parameters.Add(MakeShareable(new FJsonValueObject(SerializeExpression(ScriptIndex))));
			}
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip EX_EndFunctionParms
			Result->SetArrayField(TEXT("Parameters"), Parameters);
			break;
		}
		case EX_LetMulticastDelegate:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("LetMulticastDelegate"));
			Result->SetObjectField(TEXT("Variable"), SerializeExpression(ScriptIndex));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_ComputedJump:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("ComputedJump"));
			Result->SetObjectField(TEXT("OffsetExpression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_Jump:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("Jump"));
			Result->SetNumberField(TEXT("Offset"), ReadSkipCount(ScriptIndex));
			break;
		}
		case EX_LocalVariable:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("LocalVariable"));
			FProperty* Property = ReadPointer<FProperty>(ScriptIndex);
			FEdGraphPinType PropertyPinType;
			FPropertyTypeHelper::ConvertPropertyToPinType(Property, PropertyPinType);
			Result->SetObjectField(TEXT("VariableType"), FPropertyTypeHelper::SerializeGraphPinType(PropertyPinType, SelfScope.Get()));
			Result->SetStringField(TEXT("VariableName"), Property ? Property->GetName() : FString(TEXT("<unresolved>")));
			break;
		}
		case EX_DefaultVariable:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("DefaultVariable"));
			FProperty* Property = ReadPointer<FProperty>(ScriptIndex);
			FEdGraphPinType PropertyPinType;
			FPropertyTypeHelper::ConvertPropertyToPinType(Property, PropertyPinType);
			Result->SetObjectField(TEXT("VariableType"), FPropertyTypeHelper::SerializeGraphPinType(PropertyPinType, SelfScope.Get()));
			Result->SetStringField(TEXT("VariableName"), Property ? Property->GetName() : FString(TEXT("<unresolved>")));
			break;
		}
		case EX_InstanceVariable:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("InstanceVariable"));
			FProperty* Property = ReadPointer<FProperty>(ScriptIndex);
			FEdGraphPinType PropertyPinType;
			FPropertyTypeHelper::ConvertPropertyToPinType(Property, PropertyPinType);
			Result->SetObjectField(TEXT("VariableType"), FPropertyTypeHelper::SerializeGraphPinType(PropertyPinType, SelfScope.Get()));
			Result->SetStringField(TEXT("VariableName"), Property ? Property->GetName() : FString(TEXT("<unresolved>")));
			break;
		}
		case EX_LocalOutVariable:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("LocalOutVariable"));
			FProperty* Property = ReadPointer<FProperty>(ScriptIndex);
			FEdGraphPinType PropertyPinType;
			FPropertyTypeHelper::ConvertPropertyToPinType(Property, PropertyPinType);
			Result->SetObjectField(TEXT("VariableType"), FPropertyTypeHelper::SerializeGraphPinType(PropertyPinType, SelfScope.Get()));
			Result->SetStringField(TEXT("VariableName"), Property ? Property->GetName() : FString(TEXT("<unresolved>")));
			break;
		}
		case EX_ClassSparseDataVariable:
		{
			// UE5: sparse class data variable — same operand shape as a variable (FProperty pointer).
			Result->SetStringField(TEXT("Inst"), TEXT("ClassSparseDataVariable"));
			FProperty* Property = ReadPointer<FProperty>(ScriptIndex);
			FEdGraphPinType PropertyPinType;
			FPropertyTypeHelper::ConvertPropertyToPinType(Property, PropertyPinType);
			Result->SetObjectField(TEXT("VariableType"), FPropertyTypeHelper::SerializeGraphPinType(PropertyPinType, SelfScope.Get()));
			Result->SetStringField(TEXT("VariableName"), Property ? Property->GetName() : FString(TEXT("<unresolved>")));
			break;
		}
		case EX_PropertyConst:
		{
			// UE5: an FProperty constant.
			Result->SetStringField(TEXT("Inst"), TEXT("PropertyConst"));
			FProperty* Property = ReadPointer<FProperty>(ScriptIndex);
			FEdGraphPinType PropertyPinType;
			FPropertyTypeHelper::ConvertPropertyToPinType(Property, PropertyPinType);
			Result->SetObjectField(TEXT("PropertyType"), FPropertyTypeHelper::SerializeGraphPinType(PropertyPinType, SelfScope.Get()));
			Result->SetStringField(TEXT("PropertyName"), Property ? Property->GetName() : FString(TEXT("<unresolved>")));
			break;
		}
		case EX_InterfaceContext:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("InterfaceContext"));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_DeprecatedOp4A:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("DeprecatedOp4A"));
			break;
		}
		case EX_Nothing:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("Nothing"));
			break;
		}
		case EX_NothingInt32:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("NothingInt32"));
			Result->SetNumberField(TEXT("Value"), ReadInt(ScriptIndex));
			break;
		}
		case EX_EndOfScript:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("EndOfScript"));
			break;
		}
		case EX_IntZero:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("IntZero"));
			break;
		}
		case EX_IntOne:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("IntOne"));
			break;
		}
		case EX_True:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("True"));
			break;
		}
		case EX_False:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("False"));
			break;
		}
		case EX_NoObject:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("NoObject"));
			break;
		}
		case EX_NoInterface:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("NoInterface"));
			break;
		}
		case EX_Self:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("Self"));
			break;
		}
		case EX_Return:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("Return"));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_CallMath:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("CallMath"));
			UFunction* StackNode = ReadPointer<UFunction>(ScriptIndex);
			Result->SetStringField(TEXT("Function"), StackNode ? StackNode->GetName() : FString(TEXT("<unresolved>")));
			// EX_CallMath has no context instruction — record the (native) parent class if resolvable.
			UClass* MemberParentClass = StackNode ? StackNode->GetOuterUClass() : nullptr;
			Result->SetStringField(TEXT("ContextClass"), SafePathName(MemberParentClass));

			TArray<TSharedPtr<FJsonValue>> Parameters;
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex) && Script[ScriptIndex] != EX_EndFunctionParms) {
				Parameters.Add(MakeShareable(new FJsonValueObject(SerializeExpression(ScriptIndex))));
			}
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip EX_EndFunctionParms
			Result->SetArrayField(TEXT("Parameters"), Parameters);
			break;
		}
		case EX_FinalFunction:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("FinalFunction"));
			UFunction* StackNode = ReadPointer<UFunction>(ScriptIndex);
			Result->SetStringField(TEXT("Function"), StackNode ? StackNode->GetName() : FString(TEXT("<unresolved>")));
			TArray<TSharedPtr<FJsonValue>> Parameters;
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex) && Script[ScriptIndex] != EX_EndFunctionParms) {
				Parameters.Add(MakeShareable(new FJsonValueObject(SerializeExpression(ScriptIndex))));
			}
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip EX_EndFunctionParms
			Result->SetArrayField(TEXT("Parameters"), Parameters);
			break;
		}
		case EX_CallMulticastDelegate:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("CallMulticastDelegate"));
			UFunction* StackNode = ReadPointer<UFunction>(ScriptIndex);
			UClass* DelegateSignatureParent = StackNode ? StackNode->GetOuterUClass() : nullptr;
			const bool bIsSelfContext = DelegateSignatureParent != nullptr && DelegateSignatureParent == SelfScope.Get();

			TSharedPtr<FJsonObject> DelegateSignatureFunction = MakeShareable(new FJsonObject());
			DelegateSignatureFunction->SetBoolField(TEXT("IsSelfContext"), bIsSelfContext);
			DelegateSignatureFunction->SetStringField(TEXT("MemberParent"), SafePathName(DelegateSignatureParent));
			DelegateSignatureFunction->SetStringField(TEXT("MemberName"), StackNode ? StackNode->GetName() : FString(TEXT("<unresolved>")));
			Result->SetObjectField(TEXT("DelegateSignatureFunction"), DelegateSignatureFunction);

			Result->SetObjectField(TEXT("Delegate"), SerializeExpression(ScriptIndex));

			TArray<TSharedPtr<FJsonValue>> Parameters;
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex) && Script[ScriptIndex] != EX_EndFunctionParms) {
				Parameters.Add(MakeShareable(new FJsonValueObject(SerializeExpression(ScriptIndex))));
			}
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip EX_EndFunctionParms
			Result->SetArrayField(TEXT("Parameters"), Parameters);
			break;
		}
		case EX_VirtualFunction:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("VirtualFunction"));
			Result->SetStringField(TEXT("Function"), ReadName(ScriptIndex));
			TArray<TSharedPtr<FJsonValue>> Parameters;
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex) && Script[ScriptIndex] != EX_EndFunctionParms) {
				Parameters.Add(MakeShareable(new FJsonValueObject(SerializeExpression(ScriptIndex))));
			}
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip EX_EndFunctionParms
			Result->SetArrayField(TEXT("Parameters"), Parameters);
			break;
		}
		case EX_ClassContext:
		case EX_Context:
		case EX_Context_FailSilent:
		{
			if (Opcode == EX_ClassContext) {
				Result->SetStringField(TEXT("Inst"), TEXT("ClassContext"));
			} else if (Opcode == EX_Context) {
				Result->SetStringField(TEXT("Inst"), TEXT("Context"));
			} else {
				Result->SetStringField(TEXT("Inst"), TEXT("Context_FailSilent"));
			}

			Result->SetObjectField(TEXT("Context"), SerializeExpression(ScriptIndex));
			Result->SetNumberField(TEXT("SkipOffsetForNull"), ReadSkipCount(ScriptIndex));

			FProperty* Field = ReadPointer<FProperty>(ScriptIndex);
			if (Field) {
				FEdGraphPinType FieldPinType;
				FPropertyTypeHelper::ConvertPropertyToPinType(Field, FieldPinType);
				Result->SetObjectField(TEXT("RValuePropertyType"), FPropertyTypeHelper::SerializeGraphPinType(FieldPinType, SelfScope.Get()));
				Result->SetStringField(TEXT("RValuePropertyName"), Field->GetName());
			}

			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_IntConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("IntConst"));
			Result->SetNumberField(TEXT("Value"), ReadInt(ScriptIndex));
			break;
		}
		case EX_SkipOffsetConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("SkipOffsetConst"));
			Result->SetNumberField(TEXT("Value"), ReadSkipCount(ScriptIndex));
			break;
		}
		case EX_FloatConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("FloatConst"));
			Result->SetNumberField(TEXT("Value"), ReadFloat(ScriptIndex));
			break;
		}
		case EX_DoubleConst:
		{
			// UE5: 64-bit double constant.
			Result->SetStringField(TEXT("Inst"), TEXT("DoubleConst"));
			Result->SetNumberField(TEXT("Value"), ReadDouble(ScriptIndex));
			break;
		}
		case EX_StringConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("StringConst"));
			Result->SetStringField(TEXT("Value"), ReadString8(ScriptIndex));
			break;
		}
		case EX_UnicodeStringConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("UnicodeStringConst"));
			Result->SetStringField(TEXT("Value"), ReadString16(ScriptIndex));
			break;
		}
		case EX_TextConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("TextConst"));
			const EBlueprintTextLiteralType TextLiteralType = (EBlueprintTextLiteralType) ReadByte(ScriptIndex);
			switch (TextLiteralType) {
			case EBlueprintTextLiteralType::Empty:
				Result->SetStringField(TEXT("TextLiteralType"), TEXT("Empty"));
				break;
			case EBlueprintTextLiteralType::LocalizedText:
			{
				Result->SetStringField(TEXT("TextLiteralType"), TEXT("LocalizedText"));
				Result->SetStringField(TEXT("SourceString"), ReadString(ScriptIndex));
				Result->SetStringField(TEXT("LocalizationKey"), ReadString(ScriptIndex));
				Result->SetStringField(TEXT("LocalizationNamespace"), ReadString(ScriptIndex));
				break;
			}
			case EBlueprintTextLiteralType::InvariantText:
				Result->SetStringField(TEXT("TextLiteralType"), TEXT("InvariantText"));
				Result->SetStringField(TEXT("SourceString"), ReadString(ScriptIndex));
				break;
			case EBlueprintTextLiteralType::LiteralString:
				Result->SetStringField(TEXT("TextLiteralType"), TEXT("LiteralString"));
				Result->SetStringField(TEXT("SourceString"), ReadString(ScriptIndex));
				break;
			case EBlueprintTextLiteralType::StringTableEntry:
			{
				Result->SetStringField(TEXT("TextLiteralType"), TEXT("StringTableEntry"));
				ReadPointer<UObject>(ScriptIndex); // String Table asset (if any)
				Result->SetStringField(TEXT("TableId"), ReadString(ScriptIndex));
				Result->SetStringField(TEXT("TableKey"), ReadString(ScriptIndex));
				break;
			}
			default:
				// Unknown text literal type ⇒ operand length unknown ⇒ abort this function.
				Result->SetStringField(TEXT("TextLiteralType"), TEXT("Unknown"));
				bDisassemblyFailed = true;
				FailedOpcode = (uint8) EX_TextConst;
				FailedAtIndex = OpcodeIndex;
				break;
			}
			break;
		}
		case EX_ObjectConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("ObjectConst"));
			UObject* Pointer = ReadPointer<UObject>(ScriptIndex);
			Result->SetStringField(TEXT("Object"), SafePathName(Pointer));
			break;
		}
		case EX_SoftObjectConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("SoftObjectConst"));
			Result->SetObjectField(TEXT("Value"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_NameConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("NameConst"));
			Result->SetStringField(TEXT("Value"), ReadName(ScriptIndex));
			break;
		}
		case EX_RotationConst:
		{
			// LWC: 3 × 8-byte components (int64-width in serialization; FRotator is double at runtime).
			Result->SetStringField(TEXT("Inst"), TEXT("RotationConst"));
			Result->SetNumberField(TEXT("Pitch"), ReadDouble(ScriptIndex));
			Result->SetNumberField(TEXT("Yaw"), ReadDouble(ScriptIndex));
			Result->SetNumberField(TEXT("Roll"), ReadDouble(ScriptIndex));
			break;
		}
		case EX_VectorConst:
		{
			// LWC: 3 × double.
			Result->SetStringField(TEXT("Inst"), TEXT("VectorConst"));
			Result->SetNumberField(TEXT("X"), ReadDouble(ScriptIndex));
			Result->SetNumberField(TEXT("Y"), ReadDouble(ScriptIndex));
			Result->SetNumberField(TEXT("Z"), ReadDouble(ScriptIndex));
			break;
		}
		case EX_Vector3fConst:
		{
			// UE5: float-precision vector (3 × 32-bit float).
			Result->SetStringField(TEXT("Inst"), TEXT("Vector3fConst"));
			Result->SetNumberField(TEXT("X"), ReadFloat(ScriptIndex));
			Result->SetNumberField(TEXT("Y"), ReadFloat(ScriptIndex));
			Result->SetNumberField(TEXT("Z"), ReadFloat(ScriptIndex));
			break;
		}
		case EX_TransformConst:
		{
			// LWC: rotation(4) + translation(3) + scale(3), all 8-byte doubles.
			Result->SetStringField(TEXT("Inst"), TEXT("TransformConst"));
			const double RotX = ReadDouble(ScriptIndex);
			const double RotY = ReadDouble(ScriptIndex);
			const double RotZ = ReadDouble(ScriptIndex);
			const double RotW = ReadDouble(ScriptIndex);
			const double TransX = ReadDouble(ScriptIndex);
			const double TransY = ReadDouble(ScriptIndex);
			const double TransZ = ReadDouble(ScriptIndex);
			const double ScaleX = ReadDouble(ScriptIndex);
			const double ScaleY = ReadDouble(ScriptIndex);
			const double ScaleZ = ReadDouble(ScriptIndex);

			TSharedPtr<FJsonObject> Rotation = MakeShareable(new FJsonObject());
			Rotation->SetNumberField(TEXT("X"), RotX);
			Rotation->SetNumberField(TEXT("Y"), RotY);
			Rotation->SetNumberField(TEXT("Z"), RotZ);
			Rotation->SetNumberField(TEXT("W"), RotW);
			Result->SetObjectField(TEXT("Rotation"), Rotation);

			TSharedPtr<FJsonObject> Translation = MakeShareable(new FJsonObject());
			Translation->SetNumberField(TEXT("X"), TransX);
			Translation->SetNumberField(TEXT("Y"), TransY);
			Translation->SetNumberField(TEXT("Z"), TransZ);
			Result->SetObjectField(TEXT("Translation"), Translation);

			TSharedPtr<FJsonObject> Scale = MakeShareable(new FJsonObject());
			Scale->SetNumberField(TEXT("X"), ScaleX);
			Scale->SetNumberField(TEXT("Y"), ScaleY);
			Scale->SetNumberField(TEXT("Z"), ScaleZ);
			Result->SetObjectField(TEXT("Scale"), Scale);
			break;
		}
		case EX_StructConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("StructConst"));
			UScriptStruct* Struct = ReadPointer<UScriptStruct>(ScriptIndex);
			Result->SetStringField(TEXT("Struct"), SafePathName(Struct));
			ReadInt(ScriptIndex); //Skip serialized structure size

			if (!Struct) {
				// Unknown struct layout ⇒ cannot enumerate members ⇒ abort.
				bDisassemblyFailed = true;
				FailedOpcode = (uint8) EX_StructConst;
				FailedAtIndex = OpcodeIndex;
				break;
			}

			bool bIsEditorOnlyStruct = false;
			TSharedPtr<FJsonObject> Properties = MakeShareable(new FJsonObject());
			for (FProperty* StructProp = Struct->PropertyLink; StructProp && !bDisassemblyFailed; StructProp = StructProp->PropertyLinkNext) {
				if (StructProp->PropertyFlags & CPF_Transient || (!bIsEditorOnlyStruct && StructProp->PropertyFlags & CPF_EditorOnly)) {
					continue;
				}
				TArray<TSharedPtr<FJsonValue>> PropertyValue;
				for (int32 ArrayIter = 0; ArrayIter < StructProp->ArrayDim && !bDisassemblyFailed; ++ArrayIter) {
					PropertyValue.Add(MakeShareable(new FJsonValueObject(SerializeExpression(ScriptIndex))));
				}
				Properties->SetArrayField(StructProp->GetName(), PropertyValue);
			}
			Result->SetObjectField(TEXT("Properties"), Properties);
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip over EX_EndStructConst
			break;
		}
		case EX_SetArray:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("SetArray"));
			Result->SetObjectField(TEXT("LeftSideExpression"), SerializeExpression(ScriptIndex));
			TArray<TSharedPtr<FJsonValue>> Values;
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex) && Script[ScriptIndex] != EX_EndArray) {
				Values.Add(MakeShareable(new FJsonValueObject(SerializeExpression(ScriptIndex))));
			}
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip over EX_EndArray
			Result->SetArrayField(TEXT("Values"), Values);
			break;
		}
		case EX_ArrayConst:
		{
			FProperty* InnerProp = ReadPointer<FProperty>(ScriptIndex);
			FEdGraphPinType PropertyPinType;
			FPropertyTypeHelper::ConvertPropertyToPinType(InnerProp, PropertyPinType);
			Result->SetStringField(TEXT("Inst"), TEXT("ArrayConst"));
			Result->SetObjectField(TEXT("InnerProperty"), FPropertyTypeHelper::SerializeGraphPinType(PropertyPinType, SelfScope.Get()));

			TArray<TSharedPtr<FJsonValue>> Values;
			ReadInt(ScriptIndex); //Skip element amount
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex) && Script[ScriptIndex] != EX_EndArrayConst) {
				Values.Add(MakeShareable(new FJsonValueObject(SerializeExpression(ScriptIndex))));
			}
			if (Script.IsValidIndex(ScriptIndex)) ScriptIndex++; //Skip EX_EndArrayConst
			Result->SetArrayField(TEXT("Values"), Values);
			break;
		}
		case EX_ByteConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("ByteConst"));
			Result->SetNumberField(TEXT("Value"), ReadByte(ScriptIndex));
			break;
		}
		case EX_IntConstByte:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("IntConstByte"));
			Result->SetNumberField(TEXT("Value"), ReadByte(ScriptIndex));
			break;
		}
		case EX_Int64Const:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("Int64Const"));
			Result->SetNumberField(TEXT("Value"), (double) (int64) ReadQword(ScriptIndex));
			break;
		}
		case EX_UInt64Const:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("UInt64Const"));
			Result->SetNumberField(TEXT("Value"), (double) ReadQword(ScriptIndex));
			break;
		}
		case EX_BitFieldConst:
		{
			// UE5: assign to a single bit defined by an FProperty. [FProperty*][uint8 bit value].
			Result->SetStringField(TEXT("Inst"), TEXT("BitFieldConst"));
			FProperty* Property = ReadPointer<FProperty>(ScriptIndex);
			Result->SetStringField(TEXT("PropertyName"), Property ? Property->GetName() : FString(TEXT("<unresolved>")));
			Result->SetNumberField(TEXT("Value"), ReadByte(ScriptIndex));
			break;
		}
		case EX_FieldPathConst:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("FieldPathConst"));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_MetaCast:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("MetaCast"));
			UClass* Class = ReadPointer<UClass>(ScriptIndex);
			Result->SetStringField(TEXT("Class"), SafePathName(Class));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_DynamicCast:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("DynamicCast"));
			UClass* Class = ReadPointer<UClass>(ScriptIndex);
			Result->SetStringField(TEXT("Class"), SafePathName(Class));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_JumpIfNot:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("JumpIfNot"));
			Result->SetNumberField(TEXT("Offset"), ReadSkipCount(ScriptIndex));
			Result->SetObjectField(TEXT("Condition"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_Assert:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("Assert"));
			Result->SetNumberField(TEXT("LineNumber"), ReadWord(ScriptIndex));
			Result->SetBoolField(TEXT("Debug"), bool(ReadByte(ScriptIndex)));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_Skip:
		{
			// UE5: [CodeSkipSizeType skip][expr to possibly skip].
			Result->SetStringField(TEXT("Inst"), TEXT("Skip"));
			Result->SetNumberField(TEXT("SkipCount"), ReadSkipCount(ScriptIndex));
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_InstanceDelegate:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("InstanceDelegate"));
			Result->SetStringField(TEXT("FunctionName"), ReadName(ScriptIndex));
			break;
		}
		case EX_AddMulticastDelegate:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("AddMulticastDelegate"));
			Result->SetObjectField(TEXT("MulticastDelegate"), SerializeExpression(ScriptIndex));
			Result->SetObjectField(TEXT("Delegate"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_RemoveMulticastDelegate:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("RemoveMulticastDelegate"));
			Result->SetObjectField(TEXT("MulticastDelegate"), SerializeExpression(ScriptIndex));
			Result->SetObjectField(TEXT("Delegate"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_ClearMulticastDelegate:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("ClearMulticastDelegate"));
			Result->SetObjectField(TEXT("MulticastDelegate"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_BindDelegate:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("BindDelegate"));
			Result->SetStringField(TEXT("FunctionName"), ReadName(ScriptIndex));
			Result->SetObjectField(TEXT("Delegate"), SerializeExpression(ScriptIndex));
			Result->SetObjectField(TEXT("Object"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_PushExecutionFlow:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("PushExecutionFlow"));
			Result->SetNumberField(TEXT("Offset"), ReadSkipCount(ScriptIndex));
			break;
		}
		case EX_PopExecutionFlow:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("PopExecutionFlow"));
			break;
		}
		case EX_PopExecutionFlowIfNot:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("PopExecutionFlowIfNot"));
			Result->SetObjectField(TEXT("Condition"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_Breakpoint:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("Breakpoint"));
			break;
		}
		case EX_WireTracepoint:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("WireTracepoint"));
			break;
		}
		case EX_InstrumentationEvent:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("InstrumentationEvent"));
			const uint8 EventType = ReadByte(ScriptIndex);
			switch (EventType) {
				case EScriptInstrumentation::InlineEvent:
					Result->SetStringField(TEXT("EventType"), TEXT("InlineEvent"));
					Result->SetStringField(TEXT("EventName"), ReadName(ScriptIndex));
					break;
				case EScriptInstrumentation::Stop:            Result->SetStringField(TEXT("EventType"), TEXT("Stop")); break;
				case EScriptInstrumentation::PureNodeEntry:   Result->SetStringField(TEXT("EventType"), TEXT("PureNodeEntry")); break;
				case EScriptInstrumentation::NodeDebugSite:   Result->SetStringField(TEXT("EventType"), TEXT("NodeDebugSite")); break;
				case EScriptInstrumentation::NodeEntry:       Result->SetStringField(TEXT("EventType"), TEXT("NodeEntry")); break;
				case EScriptInstrumentation::NodeExit:        Result->SetStringField(TEXT("EventType"), TEXT("NodeExit")); break;
				case EScriptInstrumentation::PushState:       Result->SetStringField(TEXT("EventType"), TEXT("PushState")); break;
				case EScriptInstrumentation::RestoreState:    Result->SetStringField(TEXT("EventType"), TEXT("RestoreState")); break;
				case EScriptInstrumentation::ResetState:      Result->SetStringField(TEXT("EventType"), TEXT("ResetState")); break;
				case EScriptInstrumentation::SuspendState:    Result->SetStringField(TEXT("EventType"), TEXT("SuspendState")); break;
				case EScriptInstrumentation::PopState:        Result->SetStringField(TEXT("EventType"), TEXT("PopState")); break;
				case EScriptInstrumentation::TunnelEndOfThread: Result->SetStringField(TEXT("EventType"), TEXT("TunnelEndOfThread")); break;
				default:
					// Non-InlineEvent instrumentation carries no extra operand — record numeric, do NOT abort.
					Result->SetNumberField(TEXT("EventType"), EventType);
					break;
			}
			break;
		}
		case EX_Tracepoint:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("Tracepoint"));
			break;
		}
		case EX_SwitchValue:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("SwitchValue"));
			const uint16 NumCases = ReadWord(ScriptIndex);
			const CodeSkipSizeType AfterSkip = ReadSkipCount(ScriptIndex);
			Result->SetObjectField(TEXT("Expression"), SerializeExpression(ScriptIndex));
			Result->SetNumberField(TEXT("OffsetToSwitchEnd"), AfterSkip);

			TArray<TSharedPtr<FJsonValue>> Cases;
			for (uint16 CaseIndex = 0; CaseIndex < NumCases && !bDisassemblyFailed; ++CaseIndex) {
				TSharedPtr<FJsonObject> CaseObject = MakeShareable(new FJsonObject());
				CaseObject->SetObjectField(TEXT("CaseValue"), SerializeExpression(ScriptIndex));
				CaseObject->SetNumberField(TEXT("OffsetToNextCase"), ReadSkipCount(ScriptIndex));
				CaseObject->SetObjectField(TEXT("CaseResult"), SerializeExpression(ScriptIndex));
				Cases.Add(MakeShareable(new FJsonValueObject(CaseObject)));
			}
			Result->SetArrayField(TEXT("Cases"), Cases);
			Result->SetObjectField(TEXT("DefaultResult"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_ArrayGetByRef:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("ArrayGetByRef"));
			Result->SetObjectField(TEXT("ArrayExpression"), SerializeExpression(ScriptIndex));
			Result->SetObjectField(TEXT("IndexExpression"), SerializeExpression(ScriptIndex));
			break;
		}
		case EX_AutoRtfmTransact:
		{
			// UE5 AutoRTFM: [int32 id][CodeSkipSizeType offset][exprs ... EX_AutoRtfmStopTransact].
			Result->SetStringField(TEXT("Inst"), TEXT("AutoRtfmTransact"));
			Result->SetNumberField(TEXT("TransactionId"), ReadInt(ScriptIndex));
			Result->SetNumberField(TEXT("Offset"), ReadSkipCount(ScriptIndex));
			TArray<TSharedPtr<FJsonValue>> Body;
			while (!bDisassemblyFailed && Script.IsValidIndex(ScriptIndex)) {
				TSharedPtr<FJsonObject> Inner = SerializeExpression(ScriptIndex);
				Body.Add(MakeShareable(new FJsonValueObject(Inner)));
				const FString InnerInst = Inner->HasField(TEXT("Inst")) ? Inner->GetStringField(TEXT("Inst")) : FString();
				if (InnerInst == TEXT("AutoRtfmStopTransact")) break;
			}
			Result->SetArrayField(TEXT("Body"), Body);
			break;
		}
		case EX_AutoRtfmStopTransact:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("AutoRtfmStopTransact"));
			Result->SetNumberField(TEXT("TransactionId"), ReadInt(ScriptIndex));
			Result->SetNumberField(TEXT("StopMode"), (int8) ReadByte(ScriptIndex));
			break;
		}
		case EX_AutoRtfmAbortIfNot:
		{
			Result->SetStringField(TEXT("Inst"), TEXT("AutoRtfmAbortIfNot"));
			Result->SetObjectField(TEXT("Condition"), SerializeExpression(ScriptIndex));
			break;
		}
		default:
		{
			// Unknown opcode: operand length is unknown, so we cannot continue parsing this function.
			return MakeUnknownNode((uint8) Opcode, OpcodeIndex);
		}
	}

	if (!Result->HasField(TEXT("Inst"))) {
		Result->SetStringField(TEXT("Inst"), TEXT("Unknown"));
	}
	return Result;
}

TArray<TSharedPtr<FJsonValue>> FKismetBytecodeDisassemblerJson::SerializeFunction(UStruct* Function) {
	this->Script = Function->Script;
	this->SelfScope = Function->GetTypedOuter<UClass>();
	bDisassemblyFailed = false;
	FailedOpcode = 0;
	FailedAtIndex = -1;
	OpcodeHistogram.Reset();

	TArray<TSharedPtr<FJsonValue>> Statements;
	int32 ScriptIndex = 0;
	while (ScriptIndex < Script.Num() && !bDisassemblyFailed) {
		const int32 StatementIndex = ScriptIndex;
		TSharedPtr<FJsonObject> StatementObject = SerializeExpression(ScriptIndex);
		StatementObject->SetNumberField(TEXT("StatementIndex"), StatementIndex);
		Statements.Add(MakeShareable(new FJsonValueObject(StatementObject)));
	}
	return Statements;
}

bool FKismetBytecodeDisassemblerJson::FindFirstStatementOfType(UStruct* Function, int32 StartScriptIndex, uint8 ExpectedStatementOpcode, int32& OutStatementIndex) {
	this->Script = Function->Script;
	this->SelfScope = Function->GetTypedOuter<UClass>();
	bDisassemblyFailed = false;

	int32 ScriptIndex = StartScriptIndex;
	while (ScriptIndex < Script.Num() && !bDisassemblyFailed) {
		const int32 StatementIndex = ScriptIndex;
		const uint8 StatementOpcode = Script[ScriptIndex];
		SerializeExpression(ScriptIndex);
		if (StatementOpcode == ExpectedStatementOpcode) {
			OutStatementIndex = StatementIndex;
			return true;
		}
	}
	OutStatementIndex = -1;
	return false;
}

bool FKismetBytecodeDisassemblerJson::GetStatementLength(UStruct* Function, int32 ExpectedStatementIndex, int32& OutStatementLength) {
	this->Script = Function->Script;
	this->SelfScope = Function->GetTypedOuter<UClass>();
	bDisassemblyFailed = false;

	int32 ScriptIndex = 0;
	while (ScriptIndex < Script.Num() && !bDisassemblyFailed) {
		const int32 StatementIndex = ScriptIndex;
		SerializeExpression(ScriptIndex);
		if (StatementIndex == ExpectedStatementIndex) {
			OutStatementLength = ScriptIndex - StatementIndex;
			return true;
		}
	}
	OutStatementLength = -1;
	return false;
}

// -------- low-level readers (all bounds-guarded → set bDisassemblyFailed instead of over-reading) --------

int32 FKismetBytecodeDisassemblerJson::ReadInt(int32& ScriptIndex) {
	if (!Script.IsValidIndex(ScriptIndex + 3)) { bDisassemblyFailed = true; FailedAtIndex = ScriptIndex; return 0; }
	int32 Value = Script[ScriptIndex]; ++ScriptIndex;
	Value = Value | ((int32) Script[ScriptIndex] << 8); ++ScriptIndex;
	Value = Value | ((int32) Script[ScriptIndex] << 16); ++ScriptIndex;
	Value = Value | ((int32) Script[ScriptIndex] << 24); ++ScriptIndex;
	return Value;
}

uint64 FKismetBytecodeDisassemblerJson::ReadQword(int32& ScriptIndex) {
	if (!Script.IsValidIndex(ScriptIndex + 7)) { bDisassemblyFailed = true; FailedAtIndex = ScriptIndex; return 0; }
	uint64 Value = Script[ScriptIndex]; ++ScriptIndex;
	Value = Value | ((uint64) Script[ScriptIndex] << 8); ++ScriptIndex;
	Value = Value | ((uint64) Script[ScriptIndex] << 16); ++ScriptIndex;
	Value = Value | ((uint64) Script[ScriptIndex] << 24); ++ScriptIndex;
	Value = Value | ((uint64) Script[ScriptIndex] << 32); ++ScriptIndex;
	Value = Value | ((uint64) Script[ScriptIndex] << 40); ++ScriptIndex;
	Value = Value | ((uint64) Script[ScriptIndex] << 48); ++ScriptIndex;
	Value = Value | ((uint64) Script[ScriptIndex] << 56); ++ScriptIndex;
	return Value;
}

uint8 FKismetBytecodeDisassemblerJson::ReadByte(int32& ScriptIndex) {
	if (!Script.IsValidIndex(ScriptIndex)) { bDisassemblyFailed = true; FailedAtIndex = ScriptIndex; return 0; }
	return Script[ScriptIndex++];
}

FString FKismetBytecodeDisassemblerJson::ReadName(int32& ScriptIndex) {
	if (!Script.IsValidIndex(ScriptIndex + (int32) sizeof(FScriptName) - 1)) { bDisassemblyFailed = true; FailedAtIndex = ScriptIndex; return FString(); }
	const FScriptName ConstValue = *(FScriptName*) (Script.GetData() + ScriptIndex);
	ScriptIndex += sizeof(FScriptName);
	return ScriptNameToName(ConstValue).ToString();
}

uint16 FKismetBytecodeDisassemblerJson::ReadWord(int32& ScriptIndex) {
	if (!Script.IsValidIndex(ScriptIndex + 1)) { bDisassemblyFailed = true; FailedAtIndex = ScriptIndex; return 0; }
	uint16 Value = Script[ScriptIndex]; ++ScriptIndex;
	Value = Value | ((uint16) Script[ScriptIndex] << 8); ++ScriptIndex;
	return Value;
}

float FKismetBytecodeDisassemblerJson::ReadFloat(int32& ScriptIndex) {
	union { float f; int32 i; } Result;
	Result.i = ReadInt(ScriptIndex);
	return Result.f;
}

double FKismetBytecodeDisassemblerJson::ReadDouble(int32& ScriptIndex) {
	const uint64 Bits = ReadQword(ScriptIndex);
	double Value;
	FMemory::Memcpy(&Value, &Bits, sizeof(double));
	return Value;
}

CodeSkipSizeType FKismetBytecodeDisassemblerJson::ReadSkipCount(int32& ScriptIndex) {
#if SCRIPT_LIMIT_BYTECODE_TO_64KB
	return ReadWord(ScriptIndex);
#else
	static_assert(sizeof(CodeSkipSizeType) == 4, "Update this code as size changed.");
	return ReadInt(ScriptIndex);
#endif
}

FString FKismetBytecodeDisassemblerJson::ReadString8(int32& ScriptIndex) {
	FString Result;
	while (!bDisassemblyFailed) {
		const uint8 Ch = ReadByte(ScriptIndex);
		if (bDisassemblyFailed || Ch == 0) break;
		Result.AppendChar((ANSICHAR) Ch);
	}
	return Result;
}

FString FKismetBytecodeDisassemblerJson::ReadString16(int32& ScriptIndex) {
	FString Result;
	while (!bDisassemblyFailed) {
		const uint16 Ch = ReadWord(ScriptIndex);
		if (bDisassemblyFailed || Ch == 0) break;
		Result.AppendChar((TCHAR) Ch);
	}
	return Result;
}

FString FKismetBytecodeDisassemblerJson::ReadString(int32& ScriptIndex) {
	const EExprToken Opcode = (EExprToken) ReadByte(ScriptIndex);
	switch (Opcode) {
	case EX_StringConst:
		return ReadString8(ScriptIndex);
	case EX_UnicodeStringConst:
		return ReadString16(ScriptIndex);
	default:
		bDisassemblyFailed = true;
		FailedOpcode = (uint8) Opcode;
		FailedAtIndex = ScriptIndex;
		return FString();
	}
}
