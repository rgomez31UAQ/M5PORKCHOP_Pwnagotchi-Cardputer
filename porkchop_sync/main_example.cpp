/**
 * Example main.cpp for Porkchop BLE Sync
 * 
 * This shows how to use ble_client to pull captures from Sirloin
 * Integrate this into your Porkchop project's main loop
 */

#include <Arduino.h>
#include <SD.h>
#include "ble_client.h"

// SD card pins (adjust for your hardware)
#define SD_CS   5

// State
enum class AppState {
    IDLE,
    SCANNING,
    CONNECTING,
    SYNCING,
    DONE
};

static AppState appState = AppState::IDLE;
static uint32_t lastAction = 0;

// ============================================================================
// CALLBACKS - Handle received captures
// ============================================================================

void onCaptureReceived(uint8_t type, const uint8_t* data, uint16_t len) {
    // type: 0x01 = PMKID, 0x02 = Handshake
    const char* typeStr = (type == 0x01) ? "PMKID" : "Handshake";
    
    Serial.printf("[PORKCHOP] Received %s, %d bytes\n", typeStr, len);
    
    // Generate filename
    char filename[64];
    uint32_t timestamp = millis();  // Use RTC in real implementation
    snprintf(filename, sizeof(filename), "/captures/%s_%lu.bin", typeStr, timestamp);
    
    // Save to SD card
    File f = SD.open(filename, FILE_WRITE);
    if (f) {
        f.write(data, len);
        f.close();
        Serial.printf("[PORKCHOP] Saved to %s\n", filename);
    } else {
        Serial.printf("[PORKCHOP] Failed to save %s\n", filename);
    }
}

void onSyncComplete(uint16_t pmkids, uint16_t handshakes) {
    Serial.printf("[PORKCHOP] Sync complete! %d PMKIDs, %d Handshakes\n", pmkids, handshakes);
    appState = AppState::DONE;
}

// ============================================================================
// SETUP
// ============================================================================

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n[PORKCHOP] Starting BLE Sync...");
    
    // Initialize SD card
    if (!SD.begin(SD_CS)) {
        Serial.println("[PORKCHOP] SD card init failed!");
    } else {
        Serial.println("[PORKCHOP] SD card ready");
        // Create captures directory
        if (!SD.exists("/captures")) {
            SD.mkdir("/captures");
        }
    }
    
    // Initialize BLE client
    BLEClient::init();
    
    // Set callbacks
    BLEClient::setOnCapture(onCaptureReceived);
    BLEClient::setOnSyncComplete(onSyncComplete);
    
    // Start scanning for Sirloin
    BLEClient::startScan();
    appState = AppState::SCANNING;
    lastAction = millis();
}

// ============================================================================
// MAIN LOOP
// ============================================================================

void loop() {
    BLEClient::update();
    
    uint32_t now = millis();
    
    switch (appState) {
        case AppState::SCANNING:
            if (!BLEClient::isScanning()) {
                // Scan finished
                if (BLEClient::getFoundDeviceName()[0] != 0) {
                    // Found a device, connect
                    Serial.printf("[PORKCHOP] Found: %s\n", BLEClient::getFoundDeviceName());
                    appState = AppState::CONNECTING;
                    
                    if (BLEClient::connect()) {
                        Serial.println("[PORKCHOP] Connected!");
                        // Wait a moment for HELLO response
                        delay(500);
                        
                        // Check if there's anything to sync
                        uint16_t total = BLEClient::getRemotePMKIDCount() + 
                                        BLEClient::getRemoteHandshakeCount();
                        
                        if (total > 0) {
                            Serial.printf("[PORKCHOP] %d captures available, starting sync...\n", total);
                            BLEClient::startSync();
                            appState = AppState::SYNCING;
                        } else {
                            Serial.println("[PORKCHOP] Nothing to sync");
                            BLEClient::disconnect();
                            appState = AppState::DONE;
                        }
                    } else {
                        Serial.printf("[PORKCHOP] Connect failed: %s\n", BLEClient::getLastError());
                        appState = AppState::IDLE;
                    }
                } else {
                    // No device found, retry after delay
                    if (now - lastAction > 5000) {
                        Serial.println("[PORKCHOP] No Sirloin found, retrying...");
                        BLEClient::startScan();
                        lastAction = now;
                    }
                }
            }
            break;
            
        case AppState::CONNECTING:
            // Handled in SCANNING case
            break;
            
        case AppState::SYNCING:
            if (BLEClient::isSyncComplete()) {
                appState = AppState::DONE;
            }
            // Progress indicator
            static uint32_t lastProgress = 0;
            if (now - lastProgress > 1000) {
                uint16_t synced = BLEClient::getSyncedCount();
                uint16_t total = BLEClient::getTotalToSync();
                Serial.printf("[PORKCHOP] Progress: %d/%d\n", synced, total);
                lastProgress = now;
            }
            break;
            
        case AppState::DONE:
            Serial.println("[PORKCHOP] All done! Disconnecting...");
            BLEClient::disconnect();
            appState = AppState::IDLE;
            break;
            
        case AppState::IDLE:
            // Wait, then scan again
            if (now - lastAction > 30000) {  // Every 30 seconds
                Serial.println("[PORKCHOP] Scanning for Sirloin...");
                BLEClient::startScan();
                appState = AppState::SCANNING;
                lastAction = now;
            }
            break;
    }
    
    delay(10);
}
