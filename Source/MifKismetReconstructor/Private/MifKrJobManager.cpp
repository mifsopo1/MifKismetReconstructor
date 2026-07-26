// MifKismetReconstructor — implementation of the one-slot kr job record. See MifKrJobManager.h for
// the design rationale (the HTTP pump is a game-thread ticker, so single-BP jobs are atomic).
//
// Deliberately tiny: this file owns STATE, not work. The work lives in MifKrBridgeEndpoints.cpp next
// to the handlers that schedule it, so the job model stays reusable for the Wave-3 verify/census/
// classify kinds without those kinds' logic leaking in here.

#include "MifKrJobManager.h"

#if WITH_MIFBRIDGE

#include "MifReconstructorDebug.h"   // LogMifKismetReconstructor. NOT for MIF_KR_DEBUG — nothing here is gated.
#include "Dom/JsonObject.h"
#include "HAL/PlatformTime.h"
#include "Misc/DateTime.h"

namespace MifKr::Jobs
{
	// The single slot. Game-thread-only (header "THREADING"), so no synchronisation primitive appears
	// anywhere in this file — adding one would imply a contract that does not exist.
	static FJobRecord GRecord;
	static bool  GHasRecord = false;
	static int32 GJobCounter = 0;

	const TCHAR* StateName(EJobState State)
	{
		switch (State)
		{
		case EJobState::Queued:  return TEXT("queued");
		case EJobState::Running: return TEXT("running");
		case EJobState::Done:    return TEXT("done");
		case EJobState::Failed:  return TEXT("failed");
		default:                 return TEXT("none");
		}
	}

	bool IsBusy()
	{
		return GHasRecord && (GRecord.State == EJobState::Queued || GRecord.State == EJobState::Running);
	}

	bool HasRecord() { return GHasRecord; }

	const FJobRecord& Get() { return GRecord; }

	FJobRecord& Mutable() { return GRecord; }

	FString BusyMessage()
	{
		if (!IsBusy()) { return FString(); }
		// Refused, never queued: an agent that fires two requests and gets ok:true twice would believe
		// both are running. The message carries the id it must poll.
		return FString::Printf(
			TEXT("a kr job is already running (jobId=%s, kind=%s, state=%s) - poll kr_reconstruct_status until it reports done or failed, then retry. ")
			TEXT("There is ONE job slot and no queue: a second request is refused, never silently deferred."),
			*GRecord.JobId, *GRecord.Kind, StateName(GRecord.State));
	}

	bool TryBegin(const FString& Kind, FString& OutJobId, FString& OutError)
	{
		if (IsBusy())
		{
			OutError = BusyMessage();
			return false;
		}

		// Full reset: a stale counter from the previous job leaking into this one would be a silent
		// wrong number, which is worse than no number.
		GRecord = FJobRecord();
		GRecord.JobId = FString::Printf(TEXT("krjob-%d"), ++GJobCounter);
		GRecord.Kind = Kind;
		GRecord.State = EJobState::Queued;
		GRecord.Phase = TEXT("queued");
		GRecord.QueuedAtUtc = FDateTime::UtcNow();
		GRecord.QueuedAtSeconds = FPlatformTime::Seconds();
		GHasRecord = true;

		OutJobId = GRecord.JobId;
		return true;
	}

	void MarkRunning(const TCHAR* Phase)
	{
		if (!GHasRecord) { return; }
		if (GRecord.State == EJobState::Queued)
		{
			GRecord.State = EJobState::Running;
			GRecord.StartedAtSeconds = FPlatformTime::Seconds();
		}
		GRecord.Phase = Phase;
	}

	void SetPhase(const TCHAR* Phase)
	{
		if (GHasRecord) { GRecord.Phase = Phase; }
	}

	void Finish(bool bOk, const FString& Error)
	{
		if (!GHasRecord) { return; }
		if (GRecord.StartedAtSeconds <= 0.0) { GRecord.StartedAtSeconds = GRecord.QueuedAtSeconds; }
		GRecord.FinishedAtSeconds = FPlatformTime::Seconds();
		GRecord.State = bOk ? EJobState::Done : EJobState::Failed;
		GRecord.Phase = bOk ? TEXT("done") : TEXT("failed");
		GRecord.FunctionsDegraded = FMath::Max(0, GRecord.FunctionsDone - GRecord.FunctionsReconstructed);
		if (!bOk) { GRecord.Error = Error; }

		const FString Suffix = bOk ? FString() : FString::Printf(TEXT(" - %s"), *GRecord.Error);
		UE_LOG(LogMifKismetReconstructor, Log,
			TEXT("[kr job] %s (%s) %s in %d ms - functions %d/%d, events %d/%d, nodes %d%s"),
			*GRecord.JobId, *GRecord.Kind, StateName(GRecord.State), ElapsedMs(GRecord),
			GRecord.FunctionsReconstructed, GRecord.FunctionsDone,
			GRecord.EventsReconstructed, GRecord.EventsDone, GRecord.NodesCreated, *Suffix);
	}

	int32 ElapsedMs(const FJobRecord& Record)
	{
		const double Start = Record.StartedAtSeconds > 0.0 ? Record.StartedAtSeconds : Record.QueuedAtSeconds;
		if (Start <= 0.0) { return 0; }
		const double End = Record.FinishedAtSeconds > 0.0 ? Record.FinishedAtSeconds : FPlatformTime::Seconds();
		return FMath::Max(0, (int32) ((End - Start) * 1000.0));
	}

	void NotifyFunctionReconstructed(bool bOk)
	{
		// Only while a job is actually executing. An F3 press or a mif.kr.Reconstruct console run with
		// no HTTP job in flight must not move these counters — the numbers a poll returns have to
		// describe THAT job and nothing else.
		if (!GHasRecord || GRecord.State != EJobState::Running) { return; }
		++GRecord.FunctionsDone;
		if (bOk) { ++GRecord.FunctionsReconstructed; }
	}

	void NotifyEventReconstructed(bool bOk)
	{
		if (!GHasRecord || GRecord.State != EJobState::Running) { return; }
		++GRecord.EventsDone;
		if (bOk) { ++GRecord.EventsReconstructed; }
	}
}

#endif // WITH_MIFBRIDGE
