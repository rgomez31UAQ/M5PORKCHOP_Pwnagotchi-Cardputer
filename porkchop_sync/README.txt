================================================================================
PORKCHOP BLE SYNC - CLIENT CODE FOR PULLING FROM SIRLOIN
================================================================================

ARCHITECTURE
------------
SIRLOIN = BLE SERVER (already done in m5sirloin/src/sync/ble_sync.cpp)
  - Advertises as "SIRLOIN"
  - Has GATT service with Control, Data, Status characteristics
  - Waits for connection, responds to commands, sends data chunks

PORKCHOP = BLE CLIENT (this code)
  - Scans for "SIRLOIN" device
  - Connects and discovers service
  - Sends commands to request captures
  - Receives data chunks, reassembles, saves to SD

================================================================================
FILES IN THIS FOLDER
================================================================================

ble_client.h        - Header file, put in Porkchop's src/ folder
ble_client.cpp      - Implementation, put in Porkchop's src/ folder  
main_example.cpp    - Example integration, adapt to your main.cpp

================================================================================
PROTOCOL SUMMARY
================================================================================

UUIDs (must match Sirloin exactly):
  Service:  "50524b43-4841-5033-4c49-4e4b53594e4b"  (PRKCHAP3LINKSYNK)
  Control:  "50524b43-0001-4841-5033-4c494e4b5359"  (write + notify)
  Data:     "50524b43-0002-4841-5033-4c494e4b5359"  (notify only)
  Status:   "50524b43-0003-4841-5033-4c494e4b5359"  (read + notify)

Commands (Porkchop -> Sirloin via Control characteristic):
  0x01 CMD_HELLO       - Get device info + capture counts
  0x02 CMD_GET_COUNT   - Get PMKID and Handshake counts
  0x03 CMD_START_SYNC  - Start transfer: [cmd, type, index]
                         type: 0x01=PMKID, 0x02=Handshake
                         index: which capture (0-based)
  0x04 CMD_ACK_CHUNK   - Acknowledge chunk: [cmd, seq_lo, seq_hi]
  0x05 CMD_ABORT       - Abort current transfer
  0x06 CMD_MARK_SYNCED - Mark capture synced: [cmd, type, index]
  0x07 CMD_PURGE_SYNCED- Delete synced captures from Sirloin

Responses (Sirloin -> Porkchop via Control notify):
  0x81 RSP_HELLO       - [rsp, ver, pmkid_lo, pmkid_hi, hs_lo, hs_hi, flags, 0]
  0x82 RSP_COUNT       - [rsp, pmkid_lo, pmkid_hi, hs_lo, hs_hi]
  0x83 RSP_SYNC_START  - [rsp, chunks_b0, chunks_b1, chunks_b2, chunks_b3]
  0x84 RSP_OK          - [rsp]
  0x85 RSP_ERROR       - [rsp, error_code]
  0x86 RSP_ABORTED     - [rsp]
  0x87 RSP_PURGED      - [rsp, count]

Data Chunks (Sirloin -> Porkchop via Data notify):
  [seq_lo, seq_hi, data...]  - Up to 17 bytes of data per chunk
  [0xFF, 0xFF, crc_b0..b3]   - End marker with CRC32

================================================================================
SYNC FLOW
================================================================================

1. Porkchop scans for BLE devices
2. Finds "SIRLOIN", connects
3. Discovers service and characteristics
4. Subscribes to Control and Data notifications
5. Sends CMD_HELLO
6. Receives RSP_HELLO with PMKID count, Handshake count
7. For each capture (PMKIDs first, then Handshakes):
   a. Send CMD_START_SYNC [0x03, type, index]
   b. Receive RSP_SYNC_START with total chunks
   c. For each chunk:
      - Receive data chunk via Data notify
      - Send CMD_ACK_CHUNK [0x04, seq_lo, seq_hi]
   d. Receive end marker [0xFF, 0xFF, CRC32]
   e. Verify CRC32
   f. Save to SD card
   g. Send CMD_MARK_SYNCED [0x06, type, index]
8. After all captures: Send CMD_PURGE_SYNCED [0x07]
9. Disconnect

================================================================================
CAPTURE DATA FORMAT (Binary)
================================================================================

PMKID (65 bytes):
  Offset  Size  Field
  0       6     BSSID (AP MAC)
  6       6     Station MAC (client)
  12      1     SSID length
  13      32    SSID (null-padded)
  45      16    PMKID (16 bytes)
  61      4     Timestamp (uint32_t)

Handshake (variable length):
  Header (48 bytes):
    Offset  Size  Field
    0       6     BSSID (AP MAC)
    6       6     Station MAC (client)
    12      1     SSID length
    13      32    SSID (null-padded)
    45      1     Captured mask (bit 0=M1, bit 1=M2, bit 2=M3, bit 3=M4)
    46      2     Beacon length (uint16_t)

  Beacon (variable):
    [beacon data, beaconLen bytes]

  For each captured message (M1-M4) where mask bit is set:
    2       EAPOL payload length (uint16_t)
    var     EAPOL payload
    2       Full 802.11 frame length (uint16_t)
    var     Full 802.11 frame (for PCAP export)
    1       Message number (1-4)
    1       RSSI (int8_t)
    4       Timestamp (uint32_t)

================================================================================
CONVERTING TO HC22000 FORMAT
================================================================================

Once you have the binary data, convert to hashcat format:

For PMKID:
  WPA*01*<pmkid>*<bssid>*<station>*<ssid_hex>***

For Handshake (need M1+M2 or M2+M3):
  WPA*02*<mic>*<bssid>*<station>*<ssid_hex>*<nonce>*<eapol>*<msg_pair>

See hcxtools for exact format:
  https://github.com/ZerBea/hcxtools

================================================================================
PLATFORMIO.INI ADDITIONS
================================================================================

Add to your Porkchop's platformio.ini:

lib_deps = 
    h2zero/NimBLE-Arduino@^1.4.3

build_flags =
    -D CONFIG_BT_NIMBLE_ROLE_CENTRAL=1
    -D CONFIG_BT_NIMBLE_ROLE_OBSERVER=1
    -D CONFIG_BT_NIMBLE_MAX_CONNECTIONS=1

================================================================================
INTEGRATION STEPS
================================================================================

1. Copy ble_client.h and ble_client.cpp to Porkchop's src/ folder

2. Add NimBLE to platformio.ini (see above)

3. In your main code:
   
   #include "ble_client.h"
   
   // In setup():
   BLEClient::init();
   BLEClient::setOnCapture(myCaptureCB);
   BLEClient::setOnSyncComplete(mySyncCompleteCB);
   
   // To start sync:
   BLEClient::startScan();
   // When scan finds device:
   BLEClient::connect();
   // When connected:
   BLEClient::startSync();
   
   // In loop():
   BLEClient::update();

4. Implement callbacks to save captures to SD

================================================================================
TROUBLESHOOTING
================================================================================

"No device found":
  - Make sure Sirloin is powered on and in SYNC mode
  - Check Sirloin is advertising (Serial should say "advertising as SIRLOIN")
  - Bring devices closer together

"Connection failed":
  - Sirloin might be connected to something else
  - Try restarting both devices
  - Check NimBLE max connections setting

"Service not found":
  - UUID mismatch - check both use same UUIDs
  - Service might not be started on Sirloin

"CRC mismatch":
  - Data corruption during transfer
  - Will auto-retry same capture
  - If persistent, try reducing distance

"Timeout":
  - Sirloin stopped responding
  - Might be out of range
  - Reconnect and retry

================================================================================
