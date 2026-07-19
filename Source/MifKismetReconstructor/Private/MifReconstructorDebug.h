#pragma once

#include "CoreMinimal.h"

// DEBUG toggle (per the always-add-debug standard). Phase 0 is a spike → ON.
// Ship OFF (set to 0) before any release.
// Kept ON during BP_BaseNPC crash-hardening so degraded-statement reasons ([reconstruct:...]) log.
// Flip to 0 for the final clean build once BP_BaseNPC reconstructs crash-free.
#ifndef MIF_KR_DEBUG
#define MIF_KR_DEBUG 1
#endif

DECLARE_LOG_CATEGORY_EXTERN(LogMifKismetReconstructor, Log, All);
