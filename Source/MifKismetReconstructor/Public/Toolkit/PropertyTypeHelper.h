#pragma once
#include "CoreMinimal.h"
#include "Dom/JsonObject.h"
#include "EdGraph/EdGraphPin.h"

// Ported from UEAssetToolkit-Fixes (AssetDumper) → UE5.3.2. FProperty ↔ FEdGraphPinType ↔ JSON.
class MIFKISMETRECONSTRUCTOR_API FPropertyTypeHelper {
public:
    static FEdGraphPinType DeserializeGraphPinType(const TSharedRef<FJsonObject>& PinJson, UClass* SelfScope);
    static TSharedRef<FJsonObject> SerializeGraphPinType(const FEdGraphPinType& GraphPinType, UClass* SelfScope);
    static bool ConvertPropertyToPinType(const FProperty* Property, FEdGraphPinType& OutType);
};
