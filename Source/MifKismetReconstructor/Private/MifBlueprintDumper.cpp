// Phase-0 spike: in-editor console commands to disassemble a cooked Blueprint's function
// bytecode to JSON + an aggregate opcode histogram. Proves the live-in-process pointer read
// is sound in the fork and measures DDS2's real UE5.3 opcode set. DEBUG-gated; throwaway.
//
//   mif.kr.ListBP <substr>            list loaded UBlueprintGeneratedClasses matching <substr>
//   mif.kr.DumpBP  <substr | /Path>   disassemble every function → Saved/MifKismetReconstructor/<Class>/

#include "MifReconstructorDebug.h"
#include "Toolkit/KismetBytecodeDisassemblerJson.h"

#include "Engine/Blueprint.h"
#include "Engine/BlueprintGeneratedClass.h"
#include "UObject/Class.h"
#include "UObject/UObjectIterator.h"
#include "Dom/JsonObject.h"
#include "Dom/JsonValue.h"
#include "Serialization/JsonSerializer.h"
#include "Misc/FileHelper.h"
#include "Misc/Paths.h"
#include "HAL/FileManager.h"
#include "HAL/IConsoleManager.h"
#include "UObject/Script.h"
#include "Modules/ModuleManager.h"
#include "AssetRegistry/AssetRegistryModule.h"
#include "AssetRegistry/IAssetRegistry.h"
#include "AssetRegistry/ARFilter.h"
#include "AssetRegistry/AssetData.h"

#if MIF_KR_DEBUG

// Human-readable opcode name for the histogram (mirrors the disassembler's Inst names).
static FString MifKr_OpcodeName(uint8 Op)
{
	switch ((EExprToken) Op)
	{
	case EX_LocalVariable: return TEXT("LocalVariable");
	case EX_InstanceVariable: return TEXT("InstanceVariable");
	case EX_DefaultVariable: return TEXT("DefaultVariable");
	case EX_Return: return TEXT("Return");
	case EX_Jump: return TEXT("Jump");
	case EX_JumpIfNot: return TEXT("JumpIfNot");
	case EX_Assert: return TEXT("Assert");
	case EX_Nothing: return TEXT("Nothing");
	case EX_NothingInt32: return TEXT("NothingInt32");
	case EX_Let: return TEXT("Let");
	case EX_BitFieldConst: return TEXT("BitFieldConst");
	case EX_ClassContext: return TEXT("ClassContext");
	case EX_MetaCast: return TEXT("MetaCast");
	case EX_LetBool: return TEXT("LetBool");
	case EX_EndParmValue: return TEXT("EndParmValue");
	case EX_EndFunctionParms: return TEXT("EndFunctionParms");
	case EX_Self: return TEXT("Self");
	case EX_Skip: return TEXT("Skip");
	case EX_Context: return TEXT("Context");
	case EX_Context_FailSilent: return TEXT("Context_FailSilent");
	case EX_VirtualFunction: return TEXT("VirtualFunction");
	case EX_FinalFunction: return TEXT("FinalFunction");
	case EX_IntConst: return TEXT("IntConst");
	case EX_FloatConst: return TEXT("FloatConst");
	case EX_StringConst: return TEXT("StringConst");
	case EX_ObjectConst: return TEXT("ObjectConst");
	case EX_NameConst: return TEXT("NameConst");
	case EX_RotationConst: return TEXT("RotationConst");
	case EX_VectorConst: return TEXT("VectorConst");
	case EX_ByteConst: return TEXT("ByteConst");
	case EX_IntZero: return TEXT("IntZero");
	case EX_IntOne: return TEXT("IntOne");
	case EX_True: return TEXT("True");
	case EX_False: return TEXT("False");
	case EX_TextConst: return TEXT("TextConst");
	case EX_NoObject: return TEXT("NoObject");
	case EX_TransformConst: return TEXT("TransformConst");
	case EX_IntConstByte: return TEXT("IntConstByte");
	case EX_NoInterface: return TEXT("NoInterface");
	case EX_DynamicCast: return TEXT("DynamicCast");
	case EX_StructConst: return TEXT("StructConst");
	case EX_EndStructConst: return TEXT("EndStructConst");
	case EX_SetArray: return TEXT("SetArray");
	case EX_EndArray: return TEXT("EndArray");
	case EX_PropertyConst: return TEXT("PropertyConst");
	case EX_UnicodeStringConst: return TEXT("UnicodeStringConst");
	case EX_Int64Const: return TEXT("Int64Const");
	case EX_UInt64Const: return TEXT("UInt64Const");
	case EX_DoubleConst: return TEXT("DoubleConst");
	case EX_Cast: return TEXT("Cast");
	case EX_SetSet: return TEXT("SetSet");
	case EX_EndSet: return TEXT("EndSet");
	case EX_SetMap: return TEXT("SetMap");
	case EX_EndMap: return TEXT("EndMap");
	case EX_SetConst: return TEXT("SetConst");
	case EX_EndSetConst: return TEXT("EndSetConst");
	case EX_MapConst: return TEXT("MapConst");
	case EX_EndMapConst: return TEXT("EndMapConst");
	case EX_Vector3fConst: return TEXT("Vector3fConst");
	case EX_StructMemberContext: return TEXT("StructMemberContext");
	case EX_LetMulticastDelegate: return TEXT("LetMulticastDelegate");
	case EX_LetDelegate: return TEXT("LetDelegate");
	case EX_LocalVirtualFunction: return TEXT("LocalVirtualFunction");
	case EX_LocalFinalFunction: return TEXT("LocalFinalFunction");
	case EX_LocalOutVariable: return TEXT("LocalOutVariable");
	case EX_DeprecatedOp4A: return TEXT("DeprecatedOp4A");
	case EX_InstanceDelegate: return TEXT("InstanceDelegate");
	case EX_PushExecutionFlow: return TEXT("PushExecutionFlow");
	case EX_PopExecutionFlow: return TEXT("PopExecutionFlow");
	case EX_ComputedJump: return TEXT("ComputedJump");
	case EX_PopExecutionFlowIfNot: return TEXT("PopExecutionFlowIfNot");
	case EX_Breakpoint: return TEXT("Breakpoint");
	case EX_InterfaceContext: return TEXT("InterfaceContext");
	case EX_ObjToInterfaceCast: return TEXT("ObjToInterfaceCast");
	case EX_EndOfScript: return TEXT("EndOfScript");
	case EX_CrossInterfaceCast: return TEXT("CrossInterfaceCast");
	case EX_InterfaceToObjCast: return TEXT("InterfaceToObjCast");
	case EX_WireTracepoint: return TEXT("WireTracepoint");
	case EX_SkipOffsetConst: return TEXT("SkipOffsetConst");
	case EX_AddMulticastDelegate: return TEXT("AddMulticastDelegate");
	case EX_ClearMulticastDelegate: return TEXT("ClearMulticastDelegate");
	case EX_Tracepoint: return TEXT("Tracepoint");
	case EX_LetObj: return TEXT("LetObj");
	case EX_LetWeakObjPtr: return TEXT("LetWeakObjPtr");
	case EX_BindDelegate: return TEXT("BindDelegate");
	case EX_RemoveMulticastDelegate: return TEXT("RemoveMulticastDelegate");
	case EX_CallMulticastDelegate: return TEXT("CallMulticastDelegate");
	case EX_LetValueOnPersistentFrame: return TEXT("LetValueOnPersistentFrame");
	case EX_ArrayConst: return TEXT("ArrayConst");
	case EX_EndArrayConst: return TEXT("EndArrayConst");
	case EX_SoftObjectConst: return TEXT("SoftObjectConst");
	case EX_CallMath: return TEXT("CallMath");
	case EX_SwitchValue: return TEXT("SwitchValue");
	case EX_InstrumentationEvent: return TEXT("InstrumentationEvent");
	case EX_ArrayGetByRef: return TEXT("ArrayGetByRef");
	case EX_ClassSparseDataVariable: return TEXT("ClassSparseDataVariable");
	case EX_FieldPathConst: return TEXT("FieldPathConst");
	case EX_AutoRtfmTransact: return TEXT("AutoRtfmTransact");
	case EX_AutoRtfmStopTransact: return TEXT("AutoRtfmStopTransact");
	case EX_AutoRtfmAbortIfNot: return TEXT("AutoRtfmAbortIfNot");
	default: return FString::Printf(TEXT("0x%02X"), Op);
	}
}

static UBlueprintGeneratedClass* MifKr_CoerceToBPGC(UObject* Obj)
{
	if (!Obj) return nullptr;
	if (UBlueprintGeneratedClass* C = Cast<UBlueprintGeneratedClass>(Obj)) return C;
	if (UBlueprint* BP = Cast<UBlueprint>(Obj)) return Cast<UBlueprintGeneratedClass>(BP->GeneratedClass);
	return nullptr;
}

// AssetRegistry lookup — finds cooked/unloaded Blueprints (the real game content lives in paks,
// not the SDK project's loose Content, so it never appears in the Content Browser / TObjectIterator).
static void MifKr_RegistryMatches(const FString& Substr, TArray<FAssetData>& OutMatches)
{
	FAssetRegistryModule& ARM = FModuleManager::LoadModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));
	IAssetRegistry& AR = ARM.Get();

	FARFilter Filter;
	Filter.ClassPaths.Add(UBlueprintGeneratedClass::StaticClass()->GetClassPathName());
	Filter.ClassPaths.Add(UBlueprint::StaticClass()->GetClassPathName());
	Filter.bRecursiveClasses = true;

	TArray<FAssetData> Assets;
	AR.GetAssets(Filter, Assets);

	FString Needle = Substr;
	Needle.RemoveFromEnd(TEXT("_C"));
	for (const FAssetData& A : Assets)
	{
		if (A.AssetName.ToString().Contains(Needle))
		{
			OutMatches.Add(A);
		}
	}
}

static UBlueprintGeneratedClass* MifKr_ResolveBPGC(const FString& Arg, TArray<FString>& OutCandidates)
{
	// 1) explicit object/package path
	if (Arg.Contains(TEXT("/")))
	{
		if (UBlueprintGeneratedClass* C = LoadObject<UBlueprintGeneratedClass>(nullptr, *Arg)) return C;
		const FString WithC = Arg.EndsWith(TEXT("_C")) ? Arg : Arg + TEXT("_C");
		if (UBlueprintGeneratedClass* C = LoadObject<UBlueprintGeneratedClass>(nullptr, *WithC)) return C;
		if (UBlueprint* BP = LoadObject<UBlueprint>(nullptr, *Arg)) return Cast<UBlueprintGeneratedClass>(BP->GeneratedClass);
		return nullptr;
	}

	// 2) AssetRegistry (covers cooked/unloaded + loose content by name) — load the first match
	TArray<FAssetData> Matches;
	MifKr_RegistryMatches(Arg, Matches);
	UBlueprintGeneratedClass* Found = nullptr;
	for (const FAssetData& A : Matches)
	{
		OutCandidates.AddUnique(A.GetObjectPathString());
		if (!Found) Found = MifKr_CoerceToBPGC(A.GetAsset());
	}
	if (Found) return Found;

	// 3) fall back to an already-loaded class by substring
	for (TObjectIterator<UBlueprintGeneratedClass> It; It; ++It)
	{
		UBlueprintGeneratedClass* C = *It;
		if (C && C->GetName().Contains(Arg)) { OutCandidates.AddUnique(C->GetPathName()); if (!Found) Found = C; }
	}
	return Found;
}

static void MifKr_ListBP(const TArray<FString>& Args)
{
	const FString Filter = Args.Num() > 0 ? Args[0] : FString();
	int32 N = 0;
	for (TObjectIterator<UBlueprintGeneratedClass> It; It; ++It)
	{
		UBlueprintGeneratedClass* C = *It;
		if (!C) continue;
		if (Filter.IsEmpty() || C->GetName().Contains(Filter))
		{
			UE_LOG(LogMifKismetReconstructor, Display, TEXT("  %s"), *C->GetPathName());
			++N;
		}
	}
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("mif.kr.ListBP: %d loaded BPGC match '%s'"), N, *Filter);
}

static void MifKr_DumpBP(const TArray<FString>& Args)
{
	if (Args.Num() < 1)
	{
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("Usage: mif.kr.DumpBP <name-substr | /Game/Path/Asset.Asset_C>"));
		return;
	}
	const FString Arg = Args[0];

	TArray<FString> Candidates;
	UBlueprintGeneratedClass* BPGC = MifKr_ResolveBPGC(Arg, Candidates);
	if (!BPGC)
	{
		UE_LOG(LogMifKismetReconstructor, Warning,
			TEXT("No loaded UBlueprintGeneratedClass matched '%s'. Open the asset first, or pass a full path e.g. /Game/.../policeManager.policeManager_C"), *Arg);
		return;
	}
	if (Candidates.Num() > 1)
	{
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("%d classes matched '%s'; using the first: %s"), Candidates.Num(), *Arg, *BPGC->GetPathName());
	}

	const FString ClassName = BPGC->GetName();
	const FString OutDir = FPaths::ProjectSavedDir() / TEXT("MifKismetReconstructor") / ClassName;
	IFileManager::Get().MakeDirectory(*OutDir, true);

	TMap<uint8, int32> AggHist;
	int32 FnCount = 0, FnWithScript = 0, FnFailed = 0, TotalStmts = 0;
	TArray<FString> FailureLines;

	for (TFieldIterator<UFunction> It(BPGC, EFieldIteratorFlags::ExcludeSuper); It; ++It)
	{
		UFunction* Func = *It;
		if (!Func) continue;
		++FnCount;
		if (Func->Script.Num() == 0) continue;
		++FnWithScript;

		FKismetBytecodeDisassemblerJson Dis;
		TArray<TSharedPtr<FJsonValue>> Stmts = Dis.SerializeFunction(Func);
		TotalStmts += Stmts.Num();
		for (const TPair<uint8, int32>& KV : Dis.OpcodeHistogram)
		{
			AggHist.FindOrAdd(KV.Key) += KV.Value;
		}

		TSharedRef<FJsonObject> Root = MakeShareable(new FJsonObject());
		Root->SetStringField(TEXT("Function"), Func->GetName());
		Root->SetStringField(TEXT("Class"), BPGC->GetPathName());
		Root->SetNumberField(TEXT("ScriptBytes"), Func->Script.Num());
		Root->SetBoolField(TEXT("DisassemblyFailed"), Dis.bDisassemblyFailed);
		if (Dis.bDisassemblyFailed)
		{
			++FnFailed;
			Root->SetNumberField(TEXT("FailedOpcode"), Dis.FailedOpcode);
			Root->SetNumberField(TEXT("FailedAtIndex"), Dis.FailedAtIndex);
			Root->SetStringField(TEXT("FailedOpcodeName"), MifKr_OpcodeName(Dis.FailedOpcode));
			FailureLines.Add(FString::Printf(TEXT("%s: opcode 0x%02X (%s) at byte %d"),
				*Func->GetName(), Dis.FailedOpcode, *MifKr_OpcodeName(Dis.FailedOpcode), Dis.FailedAtIndex));
		}
		Root->SetArrayField(TEXT("Statements"), Stmts);

		FString OutStr;
		TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&OutStr);
		FJsonSerializer::Serialize(Root, Writer);
		FFileHelper::SaveStringToFile(OutStr, *(OutDir / (Func->GetName() + TEXT(".json"))));
	}

	// Aggregate opcode histogram (the Phase-0 signal).
	TSharedRef<FJsonObject> HistRoot = MakeShareable(new FJsonObject());
	HistRoot->SetStringField(TEXT("Class"), BPGC->GetPathName());
	HistRoot->SetNumberField(TEXT("Functions"), FnCount);
	HistRoot->SetNumberField(TEXT("FunctionsWithScript"), FnWithScript);
	HistRoot->SetNumberField(TEXT("FunctionsFailed"), FnFailed);
	HistRoot->SetNumberField(TEXT("TotalStatements"), TotalStmts);

	AggHist.ValueSort([](int32 A, int32 B) { return A > B; });
	TSharedRef<FJsonObject> HistObj = MakeShareable(new FJsonObject());
	for (const TPair<uint8, int32>& KV : AggHist)
	{
		HistObj->SetNumberField(FString::Printf(TEXT("%s (0x%02X)"), *MifKr_OpcodeName(KV.Key), KV.Key), KV.Value);
	}
	HistRoot->SetObjectField(TEXT("OpcodeHistogram"), HistObj);

	{
		FString OutStr;
		TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&OutStr);
		FJsonSerializer::Serialize(HistRoot, Writer);
		FFileHelper::SaveStringToFile(OutStr, *(OutDir / TEXT("_histogram.json")));
	}

	UE_LOG(LogMifKismetReconstructor, Display,
		TEXT("mif.kr.DumpBP %s → %d functions (%d with bytecode), %d statements, %d FAILED. Out: %s"),
		*ClassName, FnCount, FnWithScript, TotalStmts, FnFailed, *OutDir);
	for (const FString& Line : FailureLines)
	{
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("  ABORT %s"), *Line);
	}
}

static void MifKr_FindBP(const TArray<FString>& Args)
{
	const FString Filter = Args.Num() > 0 ? Args[0] : FString();
	TArray<FAssetData> Matches;
	MifKr_RegistryMatches(Filter, Matches);
	for (const FAssetData& A : Matches)
	{
		UE_LOG(LogMifKismetReconstructor, Display, TEXT("  [%s] %s"),
			*A.AssetClassPath.GetAssetName().ToString(), *A.GetObjectPathString());
	}
	UE_LOG(LogMifKismetReconstructor, Display,
		TEXT("mif.kr.FindBP: %d asset(s) match '%s' in the AssetRegistry (cooked + loose)."), Matches.Num(), *Filter);
}

static FAutoConsoleCommand GMifKrFindBP(
	TEXT("mif.kr.FindBP"),
	TEXT("List AssetRegistry Blueprints (incl. cooked/unloaded) matching a substring. Usage: mif.kr.FindBP <substr>"),
	FConsoleCommandWithArgsDelegate::CreateStatic(&MifKr_FindBP));

static FAutoConsoleCommand GMifKrListBP(
	TEXT("mif.kr.ListBP"),
	TEXT("List loaded UBlueprintGeneratedClasses matching a substring. Usage: mif.kr.ListBP <substr>"),
	FConsoleCommandWithArgsDelegate::CreateStatic(&MifKr_ListBP));

static FAutoConsoleCommand GMifKrDumpBP(
	TEXT("mif.kr.DumpBP"),
	TEXT("Disassemble a cooked Blueprint's function bytecode to JSON + opcode histogram. Usage: mif.kr.DumpBP <substr | /Path.Asset_C>"),
	FConsoleCommandWithArgsDelegate::CreateStatic(&MifKr_DumpBP));

#endif // MIF_KR_DEBUG
