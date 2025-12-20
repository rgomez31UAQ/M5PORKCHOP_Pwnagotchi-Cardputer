// DO NO HAM Mode - Passive WiFi Reconnaissance
// "BRAVO 6, GOING DARK"
#pragma once

#include <Arduino.h>
#include <esp_wifi.h>
#include <vector>
#include "oink.h"  // Reuse DetectedNetwork, CapturedPMKID, CapturedHandshake

// DNH-specific constants
static const size_t DNH_MAX_NETWORKS = 100;
static const size_t DNH_MAX_PMKIDS = 50;
static const size_t DNH_MAX_HANDSHAKES = 25;
static const uint32_t DNH_STALE_TIMEOUT = 30000;  // 30s
static const uint16_t DNH_HOP_INTERVAL = 200;     // 200ms per channel
static const uint16_t DNH_DWELL_TIME = 300;       // 300ms dwell for SSID

// DNH State Machine - simpler than OINK (no attack states)
enum class DNHState : uint8_t {
    HOPPING = 0,   // Normal channel hopping
    DWELLING       // Paused to catch beacon for SSID backfill
};

class DoNoHamMode {
public:
    static void init();
    static void start();
    static void stop();
    static void update();
    static bool isRunning() { return running; }
    
    // Seamless switching (preserves WiFi state)
    static void startSeamless();
    static void stopSeamless();
    
    // Channel info for display
    static uint8_t getCurrentChannel() { return currentChannel; }
    
    // Stats for display
    static size_t getNetworkCount() { return networks.size(); }
    static size_t getPMKIDCount() { return pmkids.size(); }
    static size_t getHandshakeCount() { return handshakes.size(); }
    
    // Frame handlers (called from shared callback)
    static void handleBeacon(const uint8_t* frame, uint16_t len, int8_t rssi);
    static void handleEAPOL(const uint8_t* frame, uint16_t len, int8_t rssi);
    
private:
    static bool running;
    static DNHState state;
    static uint8_t currentChannel;
    static uint8_t channelIndex;
    static uint32_t lastHopTime;
    static uint32_t dwellStartTime;
    static bool dwellResolved;
    
    // Data storage (separate from OINK)
    static std::vector<DetectedNetwork> networks;
    static std::vector<CapturedPMKID> pmkids;
    static std::vector<CapturedHandshake> handshakes;
    
    // Channel hopping
    static void hopToNextChannel();
    static void startDwell();
    
    // Cleanup
    static void ageOutStaleNetworks();
    static void saveAllPMKIDs();
    static void saveAllHandshakes();
    
    // Network lookup
    static int findNetwork(const uint8_t* bssid);
    static int findOrCreatePMKID(const uint8_t* bssid);
    static int findOrCreateHandshake(const uint8_t* bssid, const uint8_t* station);
};
