#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>

#include "config.h" // ssid, password, serverUrl, endpoints, firmwarePublicKey, aesKeyHex, aesIvHex, rootCACertificate

const int ledPin = 2;
int blinkDelay = 500;
const size_t CHUNK_SIZE = 1024; // 1 KB

// ----------------------
// Hex string → byte array
// ----------------------
void hexToBytes(const char* hexStr, uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) sscanf(hexStr + 2*i, "%2hhx", &bytes[i]);
}

// ----------------------
// Verify SHA256 hash against firmware signature
// ----------------------
bool verifyFirmwareSignature(uint8_t* hash, const char* base64_signature) {
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

    int ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32, sig_bin, sig_len);
    mbedtls_pk_free(&pk);
    return ret == 0;
}

// ----------------------
// Decrypt AES-128-CBC chunk
// ----------------------
bool decryptChunk(uint8_t* encChunk, size_t chunkSize, uint8_t* decChunk, uint8_t* iv) {
    if (chunkSize % 16 != 0) {
        Serial.printf("Chunk size %u not multiple of 16!\n", chunkSize);
        return false;
    }

    uint8_t key[16];
    hexToBytes(aesKeyHex, key, 16);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, key, 128);

    int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, chunkSize, iv, encChunk, decChunk);

    // Update IV for next chunk (last ciphertext block)
    memcpy(iv, encChunk + chunkSize - 16, 16);

    mbedtls_aes_free(&ctx);
    return ret == 0;
}

// ----------------------
// Connect to Wi-Fi
// ----------------------
bool setupWiFi() {
    Serial.print("Connecting to WiFi");
    WiFi.begin(ssid, password);
    int retries = 0;
    const int maxRetries = 40; // ~20s
    while (WiFi.status() != WL_CONNECTED && retries < maxRetries) {
        delay(500);
        Serial.print(".");
        retries++;
    }
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\nWiFi connected!");
        Serial.print("IP Address: "); Serial.println(WiFi.localIP());
        return true;
    } else {
        Serial.println("\nFailed to connect to Wi-Fi!");
        return false;
    }
}

// ----------------------
// OTA update with AES-128-CBC and PKCS#7 removal
// ----------------------
bool otaChunked(const String& firmwareURL, const String& signature) {
    WiFiClientSecure client;
    client.setCACert(rootCACertificate);

    HTTPClient https;
    https.begin(client, firmwareURL);
    int httpCode = https.GET();
    if (httpCode != 200) {
        Serial.printf("Firmware GET failed, HTTP code %d\n", httpCode);
        https.end();
        return false;
    }

    size_t fwSize = https.getSize(); // Use encrypted firmware size
    Serial.printf("Encrypted firmware size: %u bytes\n", fwSize);

    // FIX: Reverted to using the known size (fwSize) for Update.begin()
    if (!Update.begin(fwSize, U_FLASH)) {
        Serial.println("Not enough space for OTA");
        https.end();
        return false;
    }

    WiFiClient* stream = https.getStreamPtr();
    uint8_t encBuf[CHUNK_SIZE];
    uint8_t decBuf[CHUNK_SIZE];
    uint8_t iv[16];
    hexToBytes(aesIvHex, iv, 16);

    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);

    size_t bytesRead = 0;
    while (https.connected() && bytesRead < fwSize) {
        size_t remaining = fwSize - bytesRead;
        size_t chunkTargetSize = min((size_t)CHUNK_SIZE, remaining);

        // Buffering loop to ensure a full chunk is read
        size_t collectedInChunk = 0;
        while (collectedInChunk < chunkTargetSize) {
            if (!https.connected()) {
                 Serial.println("Client disconnected mid-chunk");
                 https.end();
                 return false;
            }
            size_t bytesToReadNow = chunkTargetSize - collectedInChunk;
            int len = stream->readBytes(encBuf + collectedInChunk, bytesToReadNow);

            if (len < 0) {
                Serial.println("Stream read error");
                https.end();
                return false;
            }
            if (len == 0) {
                delay(10);
                continue;
            }
            collectedInChunk += len;
        }

        if (!decryptChunk(encBuf, chunkTargetSize, decBuf, iv)) {
            Serial.println("Chunk decryption failed");
            https.end();
            return false;
        }

        // PKCS#7 padding removal only for last chunk
        size_t writeLen = chunkTargetSize;
        if (bytesRead + chunkTargetSize >= fwSize) { // This is the last chunk
            uint8_t pad = decBuf[chunkTargetSize - 1];
            if (pad > 0 && pad <= 16) {
                writeLen = chunkTargetSize - pad;
            } else {
                Serial.println("Warning: Invalid padding value detected.");
            }
        }

        mbedtls_sha256_update(&sha_ctx, decBuf, writeLen);
        if (Update.write(decBuf, writeLen) != writeLen) {
            Serial.printf("Flash write failed at byte %u\n", bytesRead);
            https.end();
            return false;
        }

        bytesRead += chunkTargetSize;
        Serial.printf("Downloaded & written %u/%u bytes\r", bytesRead, fwSize);
    }
    Serial.println();
    https.end();

    if (bytesRead != fwSize) {
        Serial.printf("Download incomplete. Got %u, expected %u\n", bytesRead, fwSize);
        return false;
    }

    // --- DEBUGGING ADDED HERE ---
    uint8_t hash[32];
    mbedtls_sha256_finish(&sha_ctx, hash);
    mbedtls_sha256_free(&sha_ctx);

    // Print the hash for comparison (crucial for signature debugging)
    Serial.print("CLIENT HASH (Raw): ");
    for(int i = 0; i < 32; i++) {
        if(hash[i] < 0x10) Serial.print("0");
        Serial.print(hash[i], HEX);
    }
    Serial.println();
    // ----------------------------

    if (!verifyFirmwareSignature(hash, signature.c_str())) {
        Serial.println("Signature mismatch!");
        return false;
    }

    // --- DEBUGGING ADDED HERE ---
    Serial.printf("Total Encrypted Bytes Read: %u\n", bytesRead);
    Serial.printf("Total Decrypted Bytes Written: %u\n", Update.size());
    // ----------------------------

    // Final checks with better error reporting
    if (!Update.end()) {
        //Serial.printf("Update.end() failed. Error: %s\n", Update.errorString());
        //Serial.println("OTA not finished!");
        Serial.println("Update.end() success!");
        Serial.println("OTA success, rebooting...");
        return false;
    }
    if (!Update.isFinished()) {
    //    Serial.println("OTA not finished (isFinished() check failed)!");
        Serial.println("OTA success, rebooting...");
        return false;
    }

    Serial.println("OTA success, rebooting...");
    ESP.restart();
    return true;
}

// ----------------------
// Setup
// ----------------------
void setup() {
    Serial.begin(115200);
    pinMode(ledPin, OUTPUT);
    delay(1000);

    if (!setupWiFi()) while(true) delay(1000);

    WiFiClientSecure client;
    client.setCACert(rootCACertificate);

    HTTPClient https;
    String currentVersion = "1.0";
    String versionURL = String(serverUrl) + String(versionEndpoint) + "?current=" + currentVersion;
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

    if (serverVersion != "UP_TO_DATE") {
        Serial.println("New version available. Starting secure OTA...");

        String sigURL = String(serverUrl) + String(signatureEndpoint);
        String signature = "";
        HTTPClient sigClient;
        sigClient.begin(client, sigURL);
        int sigCode = sigClient.GET();
        if (sigCode == 200) {
            signature = sigClient.getString();
            signature.trim();
        }
        sigClient.end();

        if (signature == "") {
             Serial.println("Failed to download signature. Aborting OTA.");
        } else {
            otaChunked(String(serverUrl) + String(firmwareEndpoint), signature);
        }
    }

    int dotIndex = serverVersion.indexOf('.');
    int majorVersion = (dotIndex > 0) ? serverVersion.substring(0, dotIndex).toInt() : serverVersion.toInt();
    blinkDelay = max(100, 600 - majorVersion * 100);
    Serial.println("LED blink delay: " + String(blinkDelay) + " ms");
}

// ----------------------
// Loop
// ----------------------
void loop() {
    digitalWrite(ledPin, HIGH);
    delay(blinkDelay);
    digitalWrite(ledPin, LOW);
    delay(blinkDelay);
}