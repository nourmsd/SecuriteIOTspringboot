#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#include "config.h" // contains ssid, password, serverUrl, endpoints, serverPublicKey, firmwarePublicKey

const int ledPin = 2;
int blinkDelay = 500; // default blink delay

// ----------------------
// Verify firmware signature
// ----------------------
bool verifyFirmwareSignature(uint8_t* firmware, size_t firmware_len, const char* base64_signature) {
    uint8_t sig_bin[256];
    size_t sig_len = 0;

    if (mbedtls_base64_decode(sig_bin, sizeof(sig_bin), &sig_len,
                              (const unsigned char*)base64_signature, strlen(base64_signature)) != 0) {
        Serial.println("Base64 decode failed");
        return false;
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_public_key(&pk, (const unsigned char*)firmwarePublicKey, strlen(firmwarePublicKey)+1) != 0) {
        Serial.println("Failed to parse firmware public key");
        return false;
    }

    uint8_t hash[32];
    mbedtls_sha256(firmware, firmware_len, hash, 0);

    int ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig_bin, sig_len);
    mbedtls_pk_free(&pk);

    return ret == 0;
}

// ----------------------
// WiFi setup
// ----------------------
void setupWiFi() {
    Serial.print("Connecting to WiFi");
    WiFi.begin(ssid, password);
    while(WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected! IP: " + WiFi.localIP().toString());
}

// ----------------------
// Download file via HTTPS
// ----------------------
bool downloadFile(const String& url, uint8_t* &data, size_t &size, WiFiClientSecure &client) {
    HTTPClient https;
    https.begin(client, url);

    int httpCode = https.GET();
    if (httpCode != 200) {
        Serial.printf("Download failed, HTTP code %d\n", httpCode);
        https.end();
        return false;
    }

    WiFiClient* stream = https.getStreamPtr();
    size = https.getSize();
    data = new uint8_t[size];
    int bytesRead = 0;
    while (https.connected() && bytesRead < size) {
        bytesRead += stream->readBytes(data + bytesRead, size - bytesRead);
    }

    https.end();
    return true;
}

// ----------------------
// Perform OTA
// ----------------------
bool performOTA(uint8_t* firmware, size_t size) {
    if (!Update.begin(size)) { Serial.println("Not enough space for OTA"); return false; }
    if (Update.write(firmware, size) != size) { Serial.println("Write failed"); return false; }
    if (!Update.end()) { Serial.println("Update failed"); return false; }
    if (!Update.isFinished()) { Serial.println("Update not finished"); return false; }

    Serial.println("Update successful, rebooting...");
    ESP.restart();
    return true;
}

// ----------------------
// Adjust LED blink according to major version
// ----------------------
void adjustLED(const String& version) {
    int dotIndex = version.indexOf('.');
    int majorVersion = (dotIndex > 0) ? version.substring(0, dotIndex).toInt() : version.toInt();
    blinkDelay = max(100, 600 - majorVersion * 100);
    Serial.println("LED blink delay: " + String(blinkDelay) + " ms (major version: " + String(majorVersion) + ")");
}

// ----------------------
// Setup
// ----------------------
void setup() {
    Serial.begin(115200);
    pinMode(ledPin, OUTPUT);

    setupWiFi();

    // Check server version
    WiFiClientSecure client;
    client.setInsecure();  // for testing

    String currentVersion = "1.0";
    String versionURL = String(serverUrl) + String(versionEndpoint) + "?current=" + currentVersion;

    HTTPClient https;
    https.begin(client, versionURL);
    int code = https.GET();
    String serverVersion = currentVersion;

    if (code == 200) {
        serverVersion = https.getString();
        serverVersion.trim();
        Serial.println("Server version: " + serverVersion);
    } else {
        Serial.printf("Version request failed, HTTP code: %d\n", code);
    }
    https.end();

    // For debugging: **skip OTA** to prevent restart
    if(serverVersion != "UP_TO_DATE") {
        Serial.println("New version available, but OTA skipped for debug.");
        // performOTA(...) // COMMENTED for now
    }

    adjustLED(serverVersion);
}

// ----------------------
// Loop: blink LED
// ----------------------
void loop() {
    digitalWrite(ledPin, HIGH);
    delay(blinkDelay);
    digitalWrite(ledPin, LOW);
    delay(blinkDelay);
}
