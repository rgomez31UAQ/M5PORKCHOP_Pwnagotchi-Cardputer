/**
 * BLE Client for Porkchop - Syncs captures from Sirloin
 * 
 * Add to your Porkchop project's src/ folder
 */

#ifndef BLE_CLIENT_H
#define BLE_CLIENT_H

#include <Arduino.h>

namespace BLEClient {
    // Initialize BLE client
    void init();
    
    // Deinitialize
    void deinit();
    
    // Start scanning for Sirloin devices
    void startScan();
    
    // Stop scanning
    void stopScan();
    
    // Connect to found Sirloin
    bool connect();
    
    // Disconnect
    void disconnect();
    
    // Update state machine (call in loop)
    void update();
    
    // Start sync - pull all captures
    void startSync();
    
    // Abort current sync
    void abortSync();
    
    // Status
    bool isScanning();
    bool isConnected();
    bool isSyncing();
    bool isSyncComplete();
    
    // Capture counts from Sirloin
    uint16_t getRemotePMKIDCount();
    uint16_t getRemoteHandshakeCount();
    
    // Sync progress
    uint16_t getSyncedCount();
    uint16_t getTotalToSync();
    
    // Last error
    const char* getLastError();
    
    // Get found device name (after scan)
    const char* getFoundDeviceName();
    
    // Callback types
    typedef void (*CaptureCallback)(uint8_t type, const uint8_t* data, uint16_t len);
    typedef void (*SyncCompleteCallback)(uint16_t pmkids, uint16_t handshakes);
    
    // Set callbacks
    void setOnCapture(CaptureCallback cb);
    void setOnSyncComplete(SyncCompleteCallback cb);
}

#endif // BLE_CLIENT_H
