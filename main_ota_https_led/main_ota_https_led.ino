#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>

#include "config.h" // ssid, password, serverUrl, endpoints, serverPublicKey, firmwarePublicKey, aesKeyHex, aesIvHex

const int ledPin = 2;
int blinkDelay = 500; // LED blink interval

// ----------------------
// Hex string → byte array
// ----------------------
void hexToBytes(const char* hexStr, uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hexStr + 2*i, "%2hhx", &bytes[i]);
    }
}

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
// Decrypt AES-128-CBC firmware
// ----------------------
bool decryptFirmware(uint8_t* encData, size_t encSize, uint8_t* &decData, size_t &decSize) {
    uint8_t key[16], iv[16];
    hexToBytes(aesKeyHex, key, 16);
    hexToBytes(aesIvHex, iv, 16);

    if (encSize % 16 != 0) {
        Serial.println("Encrypted firmware size not multiple of 16!");
        return false;
    }

    decData = new uint8_t[encSize];
    decSize = encSize;

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, key, 128);

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, encSize, iv_copy, encData, decData);
    mbedtls_aes_free(&ctx);

    return ret == 0;
}

// ----------------------
// Wi-Fi connect
// ----------------------
void setupWiFi() {
    Serial.print("Connecting to WiFi");
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected! IP: " + WiFi.localIP().toString());
}

// ----------------------
// Download file from server
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
// Perform OTA update
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

    WiFiClientSecure client;
    client.setInsecure();
    //client.setCACert(serverPublicKey); // validate server certificate

    // Check server version
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

    // OTA only if new version available
    if(serverVersion != "UP_TO_DATE") {
        Serial.println("New version available. Starting secure OTA...");

        // 1️⃣ Download encrypted firmware
        uint8_t* encFirmware = nullptr;
        size_t encSize = 0;
        String firmwareURL = String(serverUrl) + String(firmwareEndpoint);
        if (!downloadFile(firmwareURL, encFirmware, encSize, client)) {
            Serial.println("Firmware download failed");
            return;
        }

        // 2️⃣ Decrypt firmware
        uint8_t* firmware = nullptr;
        size_t fwSize = 0;
        if (!decryptFirmware(encFirmware, encSize, firmware, fwSize)) {
            Serial.println("Firmware decryption failed");
            delete[] encFirmware;
            return;
        }
        delete[] encFirmware;

        // 3️⃣ Download signature
        uint8_t* sig = nullptr;
        size_t sigSize = 0;
        String sigURL = String(serverUrl) + String(signatureEndpoint);
        if (!downloadFile(sigURL, sig, sigSize, client)) {
            Serial.println("Signature download failed");
            delete[] firmware;
            return;
        }
        sig[sigSize] = 0; // null-terminate

        // 4️⃣ Verify signature
        if (verifyFirmwareSignature(firmware, fwSize, (char*)sig)) {
            Serial.println("Signature verified, performing OTA...");
            performOTA(firmware, fwSize);
        } else {
            Serial.println("Invalid signature, aborting OTA");
        }

        delete[] firmware;
        delete[] sig;
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
