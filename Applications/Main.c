// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

#include "App.h"
#include "DB.h"

#include "HAP.h"
#include "HAPPlatform+Init.h"
#include "HAPPlatformAccessorySetup+Init.h"
#include "HAPPlatformBLEPeripheralManager+Init.h"
#include "HAPPlatformKeyValueStore+Init.h"
#include "HAPPlatformMFiHWAuth+Init.h"
#include "HAPPlatformMFiTokenAuth+Init.h"
#include "HAPPlatformRunLoop+Init.h"
#include "HAPPlatformKeyValueStore+SDKDomains.h"
#if IP
#include "HAPPlatformServiceDiscovery+Init.h"
#include "HAPPlatformTCPStreamManager+Init.h"
#endif

#include <signal.h>
static bool requestedFactoryReset = false;
static bool clearPairings = false;

#define PREFERRED_ADVERTISING_INTERVAL (HAPBLEAdvertisingIntervalCreateFromMilliseconds(417.5f))

/**
 * Global platform objects.
 * Only tracks objects that will be released in DeinitializePlatform.
 */
static struct {
    HAPPlatformKeyValueStore keyValueStore;
    HAPAccessoryServerOptions hapAccessoryServerOptions;
    HAPPlatform hapPlatform;
    HAPAccessoryServerCallbacks hapAccessoryServerCallbacks;

#if HAVE_NFC
    HAPPlatformAccessorySetupNFC setupNFC;
#endif

#if IP
    HAPPlatformTCPStreamManager tcpStreamManager;
#endif

    HAPPlatformMFiHWAuth mfiHWAuth;
    HAPPlatformMFiTokenAuth mfiTokenAuth;
} platform;

/**
 * HomeKit accessory server that hosts the accessory.
 */
static HAPAccessoryServerRef accessoryServer;

void HandleUpdatedState(HAPAccessoryServerRef* _Nonnull server, void* _Nullable context);

/**
 * Functions provided by App.c for each accessory application.
 */
extern void AppRelease(void);
extern void AppCreate(HAPAccessoryServerRef* server, HAPPlatformKeyValueStoreRef keyValueStore);
extern void AppInitialize(
        HAPAccessoryServerOptions* hapAccessoryServerOptions,
        HAPPlatform* hapPlatform,
        HAPAccessoryServerCallbacks* hapAccessoryServerCallbacks);
extern void AppDeinitialize();
extern void AppAccessoryServerStart(void);
extern void AccessoryServerHandleUpdatedState(HAPAccessoryServerRef* server, void* _Nullable context);
extern const HAPAccessory* AppGetAccessoryInfo();

static const HAPSetupInfo kHAPPlatformAccessorySetup_SetupInfo = {
        // Setup code: 111-22-333
        .salt = { 0x93, 0x15, 0x1A, 0x47, 0x57, 0x55, 0x3C, 0x21, 0x0B, 0x55, 0x89, 0xB8, 0xC3, 0x99, 0xA0, 0xF3 },
        .verifier = { 0x9E, 0x9C, 0xC3, 0x73, 0x9B, 0x04, 0x83, 0xC8, 0x13, 0x7C, 0x5B, 0x5F, 0xAC, 0xC5, 0x63, 0xDF, 0xF4,
                      0xF1, 0x0F, 0x39, 0x06, 0x4A, 0x20, 0x2D, 0x53, 0x2A, 0x09, 0x20, 0x3A, 0xA6, 0xBA, 0xE3, 0x1E, 0x42,
                      0x4E, 0x58, 0x4E, 0xBB, 0x44, 0x5F, 0x7F, 0xDF, 0xCC, 0x11, 0xD0, 0xF7, 0x8B, 0x35, 0xE1, 0x16, 0xA9,
                      0x79, 0x30, 0xBC, 0x37, 0x19, 0x77, 0x36, 0xB1, 0xEC, 0xD4, 0x12, 0x4C, 0xE4, 0x5D, 0xE3, 0x7E, 0x46,
                      0xA0, 0x2D, 0x10, 0x07, 0xAB, 0x48, 0x40, 0x36, 0xD5, 0x3F, 0x7F, 0xBE, 0xA5, 0xAE, 0xD0, 0x25, 0x6B,
                      0xC4, 0x9E, 0xC8, 0x5F, 0xC9, 0x4E, 0x47, 0x0D, 0xBA, 0xD3, 0x63, 0x44, 0x20, 0x01, 0x69, 0x97, 0xDD,
                      0x20, 0x54, 0x7C, 0x59, 0x78, 0x3D, 0x5C, 0x6D, 0xC7, 0x1F, 0xE6, 0xFD, 0xA0, 0x8E, 0x9B, 0x36, 0x45,
                      0x1F, 0xC1, 0x4B, 0xB5, 0x26, 0xE1, 0x8E, 0xEB, 0x4C, 0x05, 0x58, 0xD7, 0xC8, 0x80, 0xA1, 0x43, 0x7F,
                      0x5F, 0xDB, 0x75, 0x1B, 0x19, 0x57, 0x25, 0xAC, 0x5D, 0xF5, 0x8D, 0xF6, 0x7B, 0xAA, 0xB7, 0x7D, 0xE0,
                      0x36, 0xEF, 0xEA, 0xF3, 0x57, 0xAC, 0xFE, 0x12, 0x87, 0xF9, 0x31, 0x4C, 0xF7, 0x44, 0xBD, 0xB6, 0x26,
                      0x6C, 0xB4, 0x0D, 0x7C, 0x52, 0x4F, 0x85, 0x56, 0x91, 0x5D, 0x13, 0xD8, 0xDA, 0x8C, 0x45, 0x3E, 0x73,
                      0xF2, 0xF9, 0x20, 0x39, 0x24, 0x8B, 0xFB, 0xEE, 0xFD, 0x77, 0x54, 0x8D, 0x37, 0x22, 0xE8, 0x55, 0xC3,
                      0xD2, 0xF8, 0xB8, 0x23, 0xB0, 0xE2, 0x9E, 0x43, 0xAE, 0xB4, 0x37, 0xFA, 0xA7, 0x03, 0xF1, 0x82, 0x68,
                      0x4C, 0xD4, 0x86, 0xC6, 0x3E, 0xDE, 0x70, 0x11, 0x03, 0x77, 0x46, 0x59, 0x14, 0x97, 0xC6, 0xAE, 0x52,
                      0x6F, 0x03, 0x77, 0x36, 0x40, 0xBC, 0xDE, 0xCD, 0x3D, 0xE0, 0x4F, 0x69, 0x18, 0x0D, 0xCA, 0x85, 0x7E,
                      0x07, 0x30, 0xF4, 0xA1, 0xCE, 0x05, 0xB5, 0x4B, 0xE1, 0x1D, 0x43, 0xDF, 0xDB, 0x11, 0x43, 0xDE, 0x21,
                      0xAC, 0x8F, 0x03, 0x9E, 0x6E, 0x9F, 0xA8, 0xE5, 0x02, 0x06, 0x1C, 0x63, 0x34, 0x22, 0x1D, 0x39, 0xE3,
                      0x3D, 0x12, 0x2E, 0xA2, 0xF3, 0xFC, 0xB5, 0xB4, 0x16, 0x9E, 0x0E, 0x7C, 0x52, 0xC8, 0x7D, 0x50, 0x3D,
                      0xDB, 0xF5, 0x83, 0x46, 0x18, 0x92, 0x7F, 0x4D, 0x38, 0xAD, 0x0A, 0x2A, 0xBC, 0x2A, 0x50, 0x4B, 0xDF,
                      0x5D, 0xFA, 0x93, 0x41, 0x78, 0xD6, 0x45, 0x54, 0xDB, 0x44, 0x81, 0xF7, 0x5A, 0x0A, 0xDD, 0x18, 0x4F,
                      0x27, 0xD7, 0xDD, 0x5E, 0xB7, 0x3E, 0x99, 0xE6, 0xE1, 0x69, 0x35, 0x74, 0xD6, 0x98, 0x58, 0xB2, 0x13,
                      0x6F, 0xB7, 0x82, 0x72, 0xBC, 0xA6, 0x8B, 0xA3, 0x36, 0x2A, 0xCE, 0x65, 0x65, 0x51, 0x08, 0x8A, 0x3D,
                      0x04, 0x93, 0x8F, 0x01, 0x8A, 0xAB, 0x4B, 0xFC, 0x06, 0xF9 }
};

/**
 * Initialize global platform objects.
 */
static void InitializePlatform() {
    HAPError err;
    const HAPSetupInfo* setupInfo;

    // Key-value store.
    HAPPlatformKeyValueStoreCreate(
            &platform.keyValueStore, &(const HAPPlatformKeyValueStoreOptions) { .rootDirectory = ".HomeKitStore" });
    platform.hapPlatform.keyValueStore = &platform.keyValueStore;

    // Accessory setup manager. Depends on key-value store.
    static HAPPlatformAccessorySetup accessorySetup;
    HAPPlatformAccessorySetupCreate(
            &accessorySetup, &(const HAPPlatformAccessorySetupOptions) { .keyValueStore = &platform.keyValueStore });
    platform.hapPlatform.accessorySetup = &accessorySetup;

#if IP
    // TCP stream manager.
    HAPPlatformTCPStreamManagerCreate(
            &platform.tcpStreamManager,
            &(const HAPPlatformTCPStreamManagerOptions) {
                    .interfaceName = NULL,       // Listen on all available network interfaces.
                    .port = kHAPNetworkPort_Any, // Listen on unused port number from the ephemeral port range.
                    .maxConcurrentTCPStreams = kHAPIPSessionStorage_DefaultNumElements });

    // Service discovery.
    static HAPPlatformServiceDiscovery serviceDiscovery;
    HAPPlatformServiceDiscoveryCreate(
            &serviceDiscovery,
            &(const HAPPlatformServiceDiscoveryOptions) {
                    0 /* Register services on all available network interfaces. */
            });
    platform.hapPlatform.ip.serviceDiscovery = &serviceDiscovery;
#endif

#if (BLE)
    // BLE peripheral manager. Depends on key-value store.
    static HAPPlatformBLEPeripheralManagerOptions blePMOptions = { 0 };
    blePMOptions.keyValueStore = &platform.keyValueStore;

    static HAPPlatformBLEPeripheralManager blePeripheralManager;
    HAPPlatformBLEPeripheralManagerCreate(&blePeripheralManager, &blePMOptions);
    platform.hapPlatform.ble.blePeripheralManager = &blePeripheralManager;
#endif

#if HAVE_MFI_HW_AUTH
    // Apple Authentication Coprocessor provider.
    HAPPlatformMFiHWAuthCreate(&platform.mfiHWAuth);
#endif

#if HAVE_MFI_HW_AUTH
    platform.hapPlatform.authentication.mfiHWAuth = &platform.mfiHWAuth;
#endif

    // Software Token provider. Depends on key-value store.
    HAPPlatformMFiTokenAuthCreate(
            &platform.mfiTokenAuth,
            &(const HAPPlatformMFiTokenAuthOptions) { .keyValueStore = &platform.keyValueStore });

    setupInfo = &kHAPPlatformAccessorySetup_SetupInfo;
    err = HAPPlatformKeyValueStoreSet(
            accessorySetup.keyValueStore,
            kSDKKeyValueStoreDomain_Provisioning,
            kSDKKeyValueStoreKey_Provisioning_SetupInfo,
            setupInfo,
            sizeof *setupInfo);
    if (err) {
        HAPAssert(err == kHAPError_Unknown);
        HAPFatalError();
    }

    // Run loop.
    HAPPlatformRunLoopCreate(&(const HAPPlatformRunLoopOptions) { .keyValueStore = &platform.keyValueStore });

    platform.hapAccessoryServerOptions.maxPairings = kHAPPairingStorage_MinElements;

    platform.hapPlatform.authentication.mfiTokenAuth =
            HAPPlatformMFiTokenAuthIsProvisioned(&platform.mfiTokenAuth) ? &platform.mfiTokenAuth : NULL;

    platform.hapAccessoryServerCallbacks.handleUpdatedState = HandleUpdatedState;
}

/**
 * Deinitialize global platform objects.
 */
static void DeinitializePlatform() {
#if HAVE_MFI_HW_AUTH
    // Apple Authentication Coprocessor provider.
    HAPPlatformMFiHWAuthRelease(&platform.mfiHWAuth);
#endif

#if IP
    // TCP stream manager.
    HAPPlatformTCPStreamManagerRelease(&platform.tcpStreamManager);
#endif

    AppDeinitialize();

    // Run loop.
    HAPPlatformRunLoopRelease();
}

/**
 * Restore platform specific factory settings.
 */
void RestorePlatformFactorySettings(void) {
}

/**
 * Either simply passes State handling to app, or processes Factory Reset
 */
void HandleUpdatedState(HAPAccessoryServerRef* _Nonnull server, void* _Nullable context) {
    if (HAPAccessoryServerGetState(server) == kHAPAccessoryServerState_Idle && requestedFactoryReset) {
        HAPPrecondition(server);

        HAPError err;

        HAPLogInfo(&kHAPLog_Default, "A factory reset has been requested.");

        // Purge app state.
        err = HAPPlatformKeyValueStorePurgeDomain(&platform.keyValueStore, ((HAPPlatformKeyValueStoreDomain) 0x00));
        if (err) {
            HAPAssert(err == kHAPError_Unknown);
            HAPFatalError();
        }

        // Reset HomeKit state.
        err = HAPRestoreFactorySettings(&platform.keyValueStore);
        if (err) {
            HAPAssert(err == kHAPError_Unknown);
            HAPFatalError();
        }

        // Restore platform specific factory settings.
        RestorePlatformFactorySettings();

        // De-initialize App.
        AppRelease();

        requestedFactoryReset = false;

        // Re-initialize App.
        AppCreate(server, &platform.keyValueStore);

        // Restart accessory server.
        AppAccessoryServerStart();
        return;
    } else if (HAPAccessoryServerGetState(server) == kHAPAccessoryServerState_Idle && clearPairings) {
        HAPError err;
        err = HAPRemoveAllPairings(&platform.keyValueStore);
        if (err) {
            HAPAssert(err == kHAPError_Unknown);
            HAPFatalError();
        }
        AppAccessoryServerStart();
    } else {
        AccessoryServerHandleUpdatedState(server, context);
    }
}

#if IP
static void InitializeIP() {
    // Prepare accessory server storage.
    static HAPIPSession ipSessions[kHAPIPSessionStorage_DefaultNumElements];
    static uint8_t ipInboundBuffers[HAPArrayCount(ipSessions)][kHAPIPSession_DefaultInboundBufferSize];
    static uint8_t ipOutboundBuffers[HAPArrayCount(ipSessions)][kHAPIPSession_DefaultOutboundBufferSize];
    static HAPIPEventNotificationRef ipEventNotifications[HAPArrayCount(ipSessions)][kAttributeCount];
    for (size_t i = 0; i < HAPArrayCount(ipSessions); i++) {
        ipSessions[i].inboundBuffer.bytes = ipInboundBuffers[i];
        ipSessions[i].inboundBuffer.numBytes = sizeof ipInboundBuffers[i];
        ipSessions[i].outboundBuffer.bytes = ipOutboundBuffers[i];
        ipSessions[i].outboundBuffer.numBytes = sizeof ipOutboundBuffers[i];
        ipSessions[i].eventNotifications = ipEventNotifications[i];
        ipSessions[i].numEventNotifications = HAPArrayCount(ipEventNotifications[i]);
    }
    static HAPIPReadContextRef ipReadContexts[kAttributeCount];
    static HAPIPWriteContextRef ipWriteContexts[kAttributeCount];
    static uint8_t ipScratchBuffer[kHAPIPSession_DefaultScratchBufferSize];
    static HAPIPAccessoryServerStorage ipAccessoryServerStorage = {
        .sessions = ipSessions,
        .numSessions = HAPArrayCount(ipSessions),
        .readContexts = ipReadContexts,
        .numReadContexts = HAPArrayCount(ipReadContexts),
        .writeContexts = ipWriteContexts,
        .numWriteContexts = HAPArrayCount(ipWriteContexts),
        .scratchBuffer = { .bytes = ipScratchBuffer, .numBytes = sizeof ipScratchBuffer }
    };

    platform.hapAccessoryServerOptions.ip.transport = &kHAPAccessoryServerTransport_IP;
    platform.hapAccessoryServerOptions.ip.accessoryServerStorage = &ipAccessoryServerStorage;

    platform.hapPlatform.ip.tcpStreamManager = &platform.tcpStreamManager;
}
#endif

#if BLE
static void InitializeBLE() {
    static HAPBLEGATTTableElementRef gattTableElements[kAttributeCount];
    static HAPBLESessionCacheElementRef sessionCacheElements[kHAPBLESessionCache_MinElements];
    static HAPSessionRef session;
    static uint8_t procedureBytes[2048];
    static HAPBLEProcedureRef procedures[1];

    static HAPBLEAccessoryServerStorage bleAccessoryServerStorage = {
        .gattTableElements = gattTableElements,
        .numGATTTableElements = HAPArrayCount(gattTableElements),
        .sessionCacheElements = sessionCacheElements,
        .numSessionCacheElements = HAPArrayCount(sessionCacheElements),
        .session = &session,
        .procedures = procedures,
        .numProcedures = HAPArrayCount(procedures),
        .procedureBuffer = { .bytes = procedureBytes, .numBytes = sizeof procedureBytes }
    };

    platform.hapAccessoryServerOptions.ble.transport = &kHAPAccessoryServerTransport_BLE;
    platform.hapAccessoryServerOptions.ble.accessoryServerStorage = &bleAccessoryServerStorage;
    platform.hapAccessoryServerOptions.ble.preferredAdvertisingInterval = PREFERRED_ADVERTISING_INTERVAL;
    platform.hapAccessoryServerOptions.ble.preferredNotificationDuration = kHAPBLENotification_MinDuration;
}
#endif

int main(int argc HAP_UNUSED, char* _Nullable argv[_Nullable] HAP_UNUSED) {
    HAPAssert(HAPGetCompatibilityVersion() == HAP_COMPATIBILITY_VERSION);

    // Initialize global platform objects.
    InitializePlatform();

#if IP
    InitializeIP();
#endif

#if BLE
    InitializeBLE();
#endif

    // Perform Application-specific initalizations such as setting up callbacks
    // and configure any additional unique platform dependencies
    AppInitialize(&platform.hapAccessoryServerOptions, &platform.hapPlatform, &platform.hapAccessoryServerCallbacks);

    // Initialize accessory server.
    HAPAccessoryServerCreate(
            &accessoryServer,
            &platform.hapAccessoryServerOptions,
            &platform.hapPlatform,
            &platform.hapAccessoryServerCallbacks,
            /* context: */ NULL);

    // Create app object.
    AppCreate(&accessoryServer, &platform.keyValueStore);

    // Start accessory server for App.
    AppAccessoryServerStart();

    // Run main loop until explicitly stopped.
    HAPPlatformRunLoopRun();
    // Run loop stopped explicitly by calling function HAPPlatformRunLoopStop.

    // Cleanup.
    AppRelease();

    HAPAccessoryServerRelease(&accessoryServer);

    DeinitializePlatform();

    return 0;
}
