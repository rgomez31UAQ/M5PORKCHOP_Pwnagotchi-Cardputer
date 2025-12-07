// ML Feature Extraction implementation

#include "features.h"
#include <string.h>

// Static members
float FeatureExtractor::featureMeans[FEATURE_VECTOR_SIZE] = {0};
float FeatureExtractor::featureStds[FEATURE_VECTOR_SIZE] = {1};  // Default to 1 to avoid div/0
bool FeatureExtractor::normParamsLoaded = false;

void FeatureExtractor::init() {
    // Reset normalization params
    for (int i = 0; i < FEATURE_VECTOR_SIZE; i++) {
        featureMeans[i] = 0.0f;
        featureStds[i] = 1.0f;
    }
    normParamsLoaded = false;
    
    Serial.println("[ML] Feature extractor initialized");
}

WiFiFeatures FeatureExtractor::extractFromScan(const wifi_ap_record_t* ap) {
    WiFiFeatures f = {0};
    
    // Signal characteristics
    f.rssi = ap->rssi;
    f.noise = -95;  // Typical noise floor for ESP32
    f.snr = (float)(f.rssi - f.noise);
    
    // Channel info from actual scan
    f.channel = ap->primary;
    f.secondaryChannel = ap->second;  // WIFI_SECOND_CHAN_NONE, ABOVE, or BELOW
    
    // Parse authmode - covers all ESP32 auth types
    switch (ap->authmode) {
        case WIFI_AUTH_OPEN:
            f.hasWPA = false;
            f.hasWPA2 = false;
            f.hasWPA3 = false;
            break;
        case WIFI_AUTH_WEP:
            // WEP is weak, treat as no WPA
            f.hasWPA = false;
            f.hasWPA2 = false;
            f.hasWPA3 = false;
            break;
        case WIFI_AUTH_WPA_PSK:
            f.hasWPA = true;
            break;
        case WIFI_AUTH_WPA2_PSK:
            f.hasWPA2 = true;
            break;
        case WIFI_AUTH_WPA_WPA2_PSK:
            f.hasWPA = true;
            f.hasWPA2 = true;
            break;
        case WIFI_AUTH_WPA3_PSK:
            f.hasWPA3 = true;
            break;
        case WIFI_AUTH_WPA2_WPA3_PSK:
            f.hasWPA2 = true;
            f.hasWPA3 = true;
            break;
        case WIFI_AUTH_WAPI_PSK:
            // Chinese WLAN standard, treat as WPA2 equivalent
            f.hasWPA2 = true;
            break;
        case WIFI_AUTH_WPA2_ENTERPRISE:
            f.hasWPA2 = true;
            break;
        default:
            break;
    }
    
    // Check if hidden SSID
    f.isHidden = (ap->ssid[0] == 0);
    
    // PHY capabilities from actual ESP-IDF scan data
    // These are REAL values, not hardcoded!
    f.htCapabilities = 0;
    if (ap->phy_11b) f.htCapabilities |= 0x01;  // 802.11b support
    if (ap->phy_11g) f.htCapabilities |= 0x02;  // 802.11g support  
    if (ap->phy_11n) f.htCapabilities |= 0x04;  // 802.11n (HT) support
    if (ap->phy_lr)  f.htCapabilities |= 0x08;  // Long Range mode (ESP32 specific)
    
    // Supported rates estimation based on PHY modes
    f.supportedRates = 0;
    if (ap->phy_11b) f.supportedRates += 4;   // 1, 2, 5.5, 11 Mbps
    if (ap->phy_11g) f.supportedRates += 8;   // 6, 9, 12, 18, 24, 36, 48, 54 Mbps
    if (ap->phy_11n) f.supportedRates += 8;   // MCS 0-7 rates
    
    // Country code availability (indicates more legitimate AP)
    // ap->country has cc[3] field - if populated, AP broadcasts country IE
    if (ap->country.cc[0] != 0) {
        f.vendorIECount++;  // Use vendorIECount to indicate country IE present
    }
    
    // Note: beaconInterval, capability, hasWPS, beaconJitter, responseTime
    // are NOT available from scan API - would need promiscuous mode
    // These remain 0 (default) for now
    
    // Anomaly score calculation based on available data
    f.anomalyScore = 0.0f;
    
    // Very strong signal is suspicious (possible rogue AP nearby)
    if (f.rssi > -30) {
        f.anomalyScore += 0.3f;
    }
    
    // Open network with no encryption
    if (ap->authmode == WIFI_AUTH_OPEN) {
        f.anomalyScore += 0.2f;
    }
    
    // WEP is outdated and suspicious
    if (ap->authmode == WIFI_AUTH_WEP) {
        f.anomalyScore += 0.2f;
    }
    
    // Hidden SSID
    if (f.isHidden) {
        f.anomalyScore += 0.1f;
    }
    
    // No 11n support in 2024+ is unusual
    if (!ap->phy_11n) {
        f.anomalyScore += 0.1f;
    }
    
    return f;
}

WiFiFeatures FeatureExtractor::extractFromBeacon(const uint8_t* frame, uint16_t len, int8_t rssi) {
    WiFiFeatures f = {0};
    
    if (len < 36) return f;  // Minimum beacon frame size
    
    // Frame control is first 2 bytes, skip to fixed params at offset 24
    // Fixed params: timestamp(8) + beacon_interval(2) + capability(2)
    
    f.rssi = rssi;
    f.noise = -95;
    f.snr = (float)(f.rssi - f.noise);
    
    f.beaconInterval = parseBeaconInterval(frame, len);
    f.capability = parseCapability(frame, len);
    
    // isHidden is determined from SSID IE in parseIEs, initialize to false
    f.isHidden = false;
    f.hasWPS = false;  // Determined from IEs
    f.hasWPA = false;
    f.hasWPA2 = false;
    f.hasWPA3 = false;
    
    // Parse Information Elements (SSID, WPA, WPS, etc.)
    parseIEs(frame, len, f);
    
    // Extract channel from DS Parameter Set IE if available (done in parseIEs)
    // If not found, channel remains 0
    
    return f;
}

ProbeFeatures FeatureExtractor::extractFromProbe(const uint8_t* frame, uint16_t len, int8_t rssi) {
    ProbeFeatures p = {0};
    
    if (len < 24) return p;  // Minimum frame size
    
    // Source MAC is at offset 10
    memcpy(p.macPrefix, frame + 10, 3);
    
    // Check if randomized MAC (bit 1 of first byte set = locally administered)
    p.randomMAC = isRandomMAC(frame + 10);
    
    p.avgRSSI = rssi;
    p.probeCount = 1;
    p.lastSeen = millis();
    
    return p;
}

void FeatureExtractor::toFeatureVector(const WiFiFeatures& features, float* output) {
    // Fill feature vector - order matters for model!
    output[0] = (float)features.rssi;
    output[1] = (float)features.noise;
    output[2] = features.snr;
    output[3] = (float)features.channel;
    output[4] = (float)features.secondaryChannel;
    output[5] = (float)features.beaconInterval;
    output[6] = (float)(features.capability & 0xFF);
    output[7] = (float)((features.capability >> 8) & 0xFF);
    output[8] = features.hasWPS ? 1.0f : 0.0f;
    output[9] = features.hasWPA ? 1.0f : 0.0f;
    output[10] = features.hasWPA2 ? 1.0f : 0.0f;
    output[11] = features.hasWPA3 ? 1.0f : 0.0f;
    output[12] = features.isHidden ? 1.0f : 0.0f;
    output[13] = (float)features.responseTime;
    output[14] = (float)features.beaconCount;
    output[15] = features.beaconJitter;
    output[16] = features.respondsToProbe ? 1.0f : 0.0f;
    output[17] = (float)features.probeResponseTime;
    output[18] = (float)features.vendorIECount;
    output[19] = (float)features.supportedRates;
    output[20] = (float)features.htCapabilities;
    output[21] = (float)features.vhtCapabilities;
    output[22] = features.anomalyScore;
    // Pad remaining with zeros
    for (int i = 23; i < FEATURE_VECTOR_SIZE; i++) {
        output[i] = 0.0f;
    }
    
    // Apply normalization if available
    if (normParamsLoaded) {
        for (int i = 0; i < FEATURE_VECTOR_SIZE; i++) {
            output[i] = normalize(output[i], featureMeans[i], featureStds[i]);
        }
    }
}

void FeatureExtractor::probeToFeatureVector(const ProbeFeatures& features, float* output) {
    memset(output, 0, FEATURE_VECTOR_SIZE * sizeof(float));
    
    output[0] = (float)features.macPrefix[0];
    output[1] = (float)features.macPrefix[1];
    output[2] = (float)features.macPrefix[2];
    output[3] = (float)features.probeCount;
    output[4] = (float)features.uniqueSSIDCount;
    output[5] = features.randomMAC ? 1.0f : 0.0f;
    output[6] = (float)features.avgRSSI;
}

std::vector<float> FeatureExtractor::extractBatchFeatures(const std::vector<WiFiFeatures>& networks) {
    std::vector<float> batch;
    batch.reserve(networks.size() * FEATURE_VECTOR_SIZE);
    
    float vec[FEATURE_VECTOR_SIZE];
    for (const auto& net : networks) {
        toFeatureVector(net, vec);
        batch.insert(batch.end(), vec, vec + FEATURE_VECTOR_SIZE);
    }
    
    return batch;
}

void FeatureExtractor::setNormalizationParams(const float* means, const float* stds) {
    memcpy(featureMeans, means, FEATURE_VECTOR_SIZE * sizeof(float));
    memcpy(featureStds, stds, FEATURE_VECTOR_SIZE * sizeof(float));
    normParamsLoaded = true;
    
    Serial.println("[ML] Normalization parameters loaded");
}

uint16_t FeatureExtractor::parseBeaconInterval(const uint8_t* frame, uint16_t len) {
    if (len < 34) return 100;  // Default beacon interval
    // Beacon interval at offset 32 (after 24 byte header + 8 byte timestamp)
    return frame[32] | (frame[33] << 8);
}

uint16_t FeatureExtractor::parseCapability(const uint8_t* frame, uint16_t len) {
    if (len < 36) return 0;
    // Capability at offset 34
    return frame[34] | (frame[35] << 8);
}

void FeatureExtractor::parseIEs(const uint8_t* frame, uint16_t len, WiFiFeatures& features) {
    // IEs start at offset 36 (after fixed params)
    uint16_t offset = 36;
    
    while (offset + 2 < len) {
        uint8_t id = frame[offset];
        uint8_t ieLen = frame[offset + 1];
        
        if (offset + 2 + ieLen > len) break;
        
        const uint8_t* ieData = frame + offset + 2;
        
        switch (id) {
            case 0:  // SSID
                // Check for hidden SSID (zero-length or all nulls)
                if (ieLen == 0) {
                    features.isHidden = true;
                } else {
                    bool allNull = true;
                    for (uint8_t i = 0; i < ieLen && i < 32; i++) {
                        if (ieData[i] != 0) { allNull = false; break; }
                    }
                    features.isHidden = allNull;
                }
                break;
                
            case 1:  // Supported Rates
                features.supportedRates = ieLen;
                break;
                
            case 3:  // DS Parameter Set (channel)
                if (ieLen >= 1) {
                    features.channel = ieData[0];
                }
                break;
                
            case 45:  // HT Capabilities (802.11n)
                features.htCapabilities |= 0x04;  // Set 11n flag
                break;
                
            case 48:  // RSN (WPA2/WPA3)
                features.hasWPA2 = true;
                // Check for WPA3 SAE in RSN
                if (ieLen >= 8) {
                    // Parse AKM suite to detect SAE (WPA3)
                    // Simplified: just mark WPA2 for now
                }
                break;
                
            case 191:  // VHT Capabilities (802.11ac)
                features.vhtCapabilities = 1;
                break;
                
            case 221:  // Vendor Specific
                features.vendorIECount++;
                // Check for WPS OUI: 00:50:F2:04
                if (ieLen >= 4) {
                    if (ieData[0] == 0x00 && ieData[1] == 0x50 &&
                        ieData[2] == 0xF2 && ieData[3] == 0x04) {
                        features.hasWPS = true;
                    }
                    // Check for WPA OUI: 00:50:F2:01
                    if (ieData[0] == 0x00 && ieData[1] == 0x50 &&
                        ieData[2] == 0xF2 && ieData[3] == 0x01) {
                        features.hasWPA = true;
                    }
                }
                break;
        }
        
        offset += 2 + ieLen;
    }
}

bool FeatureExtractor::isRandomMAC(const uint8_t* mac) {
    // Locally administered bit (bit 1 of first octet)
    return (mac[0] & 0x02) != 0;
}

float FeatureExtractor::normalize(float value, float mean, float std) {
    if (std < 0.001f) return 0.0f;
    return (value - mean) / std;
}
