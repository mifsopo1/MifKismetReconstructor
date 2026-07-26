// MifKismetReconstructor — the ONE-SLOT job record behind kr_reconstruct_request / kr_reconstruct_status.
//
// WHY A JOB MODEL AT ALL, given the jobs are atomic (K2 §"The polling reality", VERIFIED):
// FHttpServerModule is an FTSTickerObjectBase (HttpServerModule.h:25) whose Tick (:60) runs on the GAME
// THREAD. While a synchronous reconstruct runs, no HTTP request is even READ OFF THE SOCKET — so
// mid-Blueprint progress polling is not "unimplemented", it is PHYSICALLY IMPOSSIBLE. This file must
// therefore never pretend otherwise. What request/poll DOES buy, and all it buys, is:
//   1. the requester never holds an HTTP connection open across a multi-second editor stall
//      (the bridge's read timeout would fire and the caller would report a failure that did not happen),
//   2. the result survives a client disconnect/reconnect — poll-after-done always works,
//   3. the jobId + the flushed BEGIN log line give crash forensics a name for the culprit.
// Every payload therefore carries the honesty note; see H_kr_reconstruct_status.
//
// ONE SLOT, NO QUEUE (K2 "Shared job model"). A second request while state ∈ {queued, running} is
// REFUSED naming the running jobId and kind. A queue would silently reorder work an agent believes is
// sequential; batching belongs to the caller, which already has MifBridge's `batch`.
//
// THREADING: game thread only, by construction — the request handler runs on the game thread
// (MifBridgeServer.cpp hops there before dispatch) and the deferred slice runs from
// GEditor->GetTimerManager(). A plain file-static record is therefore race-free; no lock is taken and
// none is needed. Do not call anything here from a worker thread.
//
// LIFETIME: in-memory only. After an editor restart the record is gone and kr_reconstruct_status
// answers found:false — stated in the status payload rather than left for a caller to discover.
#pragma once

#include "CoreMinimal.h"

#if WITH_MIFBRIDGE

class FJsonObject;

namespace MifKr::Jobs
{
	enum class EJobState : uint8 { None, Queued, Running, Done, Failed };

	/** Lowercase wire spelling: "none" | "queued" | "running" | "done" | "failed". */
	const TCHAR* StateName(EJobState State);

	/** POD. Every field is written on the game thread and read on the game thread. */
	struct FJobRecord
	{
		FString   JobId;                 // "krjob-<n>", monotonic within one editor session
		FString   Kind;                  // "reconstruct" (v1; verify/census/classify are Wave 3)
		EJobState State = EJobState::None;
		FString   Phase;                 // resolving | minting | reconstructing | compiling | saving | done

		// --- request echo (so a poll is self-describing without the caller keeping state) ---
		FString SourceAsset;             // exactly what the caller passed
		FString SourceClassPath;         // what it RESOLVED to — the two differ and both matter
		FString BpName;
		FString Mode;                    // "copy" | "function"
		FString Variant;                 // copy mode only
		FString TargetPath;
		FString FunctionName;            // function mode only

		// --- timing (FPlatformTime::Seconds deltas; wall clock for the human-readable stamp) ---
		FDateTime QueuedAtUtc;
		double    QueuedAtSeconds = 0.0;
		double    StartedAtSeconds = 0.0;
		double    FinishedAtSeconds = 0.0;

		// --- progress -------------------------------------------------------------------------
		// FunctionsTotalEstimate is named "Estimate" on the wire and it is not padding: the
		// authoritative per-function gate is the engine-static CopyFunctionStubs
		// (CompiledBlueprintCopyAction.cpp:551), which cannot be linked from here. The DONE counts are
		// authoritative (they are fed by the delegates the engine actually invoked); the total is advisory.
		int32 FunctionsTotalEstimate = 0;
		int32 FunctionsDone = 0;            // delegate invocations seen (copy mode) or 1 (function mode)
		int32 FunctionsReconstructed = 0;   // of those, the ones that returned true
		int32 FunctionsDegraded = 0;        // FunctionsDone - FunctionsReconstructed, tallied explicitly
		int32 EventsDone = 0;
		int32 EventsReconstructed = 0;
		int32 NodesCreated = 0;             // graph Nodes.Num() delta — NOT a decompiler counter

		// --- compile --------------------------------------------------------------------------
		// bCompileMeasured is false for copy mode ON PURPOSE: the engine compiles inside
		// CreateEditableBlueprintCopy and we do not own that FCompilerResultsLog. Reporting errors:0
		// there would be a fabricated number. See the status payload's compile.measured field.
		bool    bCompileMeasured = false;
		int32   CompileErrors = 0;
		int32   CompileWarnings = 0;
		FString FirstError;

		FString                 Error;    // set iff State == Failed
		TSharedPtr<FJsonObject> Result;   // kind-specific payload, filled at Finish
	};

	/** True while State ∈ {Queued, Running} — i.e. the single slot is taken. */
	bool IsBusy();

	/** False until the first job of this editor session has been requested. */
	bool HasRecord();

	/** The retained record: the running job, or the last completed one. */
	const FJobRecord& Get();

	/** Mutable access for the owning handler / deferred slice. Game thread only. */
	FJobRecord& Mutable();

	/** The busy-refusal text, naming the running jobId/kind/state and what to poll. ONE source of
	 *  truth: both the request handler's early pre-check and TryBegin's own guard use this, so the two
	 *  refusals can never drift into saying different things. Empty string when the slot is free. */
	FString BusyMessage();

	/** Take the slot. Returns false and fills OutError with BusyMessage() when IsBusy(). On success the
	 *  record is RESET and State becomes Queued. */
	bool TryBegin(const FString& Kind, FString& OutJobId, FString& OutError);

	/** Queued → Running, stamping StartedAtSeconds. Idempotent. */
	void MarkRunning(const TCHAR* Phase);

	void SetPhase(const TCHAR* Phase);

	/** Running → Done (bOk) or Failed (!bOk), stamping FinishedAtSeconds. Error is ignored when bOk. */
	void Finish(bool bOk, const FString& Error);

	/** Milliseconds from start (or queue, if the slice has not run yet) to finish (or now). */
	int32 ElapsedMs(const FJobRecord& Record);

	// --- progress feed ---------------------------------------------------------------------------
	// Called from the engine-delegate lambdas already bound in MifKismetReconstructorModule.cpp. They
	// are NO-OPS unless a job is Running, so the F3 hook and the console commands are unaffected: a
	// user pressing F3 with no HTTP job in flight increments nothing. This is the whole progress
	// mechanism — zero engine change, and it counts exactly the reconstructions the engine performed.
	void NotifyFunctionReconstructed(bool bOk);
	void NotifyEventReconstructed(bool bOk);
}

#endif // WITH_MIFBRIDGE
