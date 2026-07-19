#pragma once
#include "CoreMinimal.h"
#include "Dom/JsonObject.h"
#include "UObject/Script.h"   // CodeSkipSizeType, EExprToken (not pulled in by CoreMinimal)

// Ported from UEAssetToolkit-Fixes (AssetDumper) → UE5.3.2 + hardened.
// Walks a live UStruct::Script bytecode array into a JSON statement stream.
// SAFE in-process: the cooked BPGC is loaded so the raw pointers baked into Script are live.
class MIFKISMETRECONSTRUCTOR_API FKismetBytecodeDisassemblerJson {
public:
	/** Converts a single expression into a json object. On an unknown opcode, sets bDisassemblyFailed and returns an "Unknown" node. */
	TSharedPtr<FJsonObject> SerializeExpression(int32& ScriptIndex);

	/** Parses a block of statements until the end of Script (or until an unknown opcode aborts). */
	TArray<TSharedPtr<FJsonValue>> SerializeFunction(UStruct* Function);

	/** Computes length of the statement in bytes and returns it. Returns false if given index does not correspond to any statement. */
	bool GetStatementLength(UStruct* Function, int32 StatementIndex, int32& OutStatementLength);

	/** Returns index of the first statement using given opcode. */
	bool FindFirstStatementOfType(UStruct* Function, int32 StartIndex, uint8 StatementOpcode, int32& OutStatementIndex);

	// --- Phase-0 instrumentation / hardening state (reset per SerializeFunction call) ---
	/** Set true when an unknown opcode is hit (operand length unknown → cannot continue). */
	bool bDisassemblyFailed = false;
	/** The opcode that aborted disassembly (valid only when bDisassemblyFailed). */
	uint8 FailedOpcode = 0;
	/** Script byte-offset at which disassembly aborted (valid only when bDisassemblyFailed). */
	int32 FailedAtIndex = -1;
	/** Opcode → occurrence count across the whole function (the Phase-0 histogram signal). */
	TMap<uint8, int32> OpcodeHistogram;

private:
	TWeakObjectPtr<UClass> SelfScope;
	TArray<uint8> Script;

	//Begin script bytecode parsing methods
	int32 ReadInt(int32& ScriptIndex);
	uint64 ReadQword(int32& ScriptIndex);
	uint8 ReadByte(int32& ScriptIndex);
	FString ReadName(int32& ScriptIndex);
	uint16 ReadWord(int32& ScriptIndex);
	float ReadFloat(int32& ScriptIndex);
	double ReadDouble(int32& ScriptIndex);   // NEW: UE5 LWC 8-byte constants
	CodeSkipSizeType ReadSkipCount(int32& ScriptIndex);
	FString ReadString8(int32& ScriptIndex);
	FString ReadString16(int32& ScriptIndex);
	FString ReadString(int32& ScriptIndex);

	template <typename T>
	T* ReadPointer(int32& ScriptIndex) {
		return (T*)ReadQword(ScriptIndex);
	}
	//End script bytecode parsing methods

	/** Records an unknown-opcode abort and returns a diagnostic node. */
	TSharedPtr<FJsonObject> MakeUnknownNode(uint8 Opcode, int32 AtIndex);
	/** Null-safe path/name for a possibly-unresolved bytecode pointer. */
	static FString SafePathName(const UObject* Object);
};
