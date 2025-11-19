package com.esp32.securiteIOT;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@RestController
@RequestMapping("/ota")
public class OtaController {

    private static final String FIRMWARE_ENC_PATH = "firmware/firmware.enc";
    private static final String FIRMWARE_BIN_PATH = "firmware/firmware.bin";
    private static final String VERSION_PATH = "firmware/version.txt";

    private static final Logger logger = LoggerFactory.getLogger(OtaController.class);

    // AES key & IV (not used here for signing) — keep for reference
    @Value("${ota.aes.key}")
    private String aesKeyHex;

    @Value("${ota.aes.iv}")
    private String aesIvHex;

    private static byte[] hexStringToByteArray(String s) {
        if (s.length() % 2 != 0) throw new IllegalArgumentException("Hex string must have even length");
        int len = s.length();
        byte[] data = new byte[len/2];
        for (int i=0;i<len;i+=2) data[i/2] = (byte)((Character.digit(s.charAt(i),16)<<4) + Character.digit(s.charAt(i+1),16));
        return data;
    }

    private PrivateKey loadPrivateKey() throws Exception {
        InputStream is = getClass().getClassLoader().getResourceAsStream("new_private.pem");
        if (is == null) {
            logger.error("Private key not found in resources");
            throw new FileNotFoundException("new_private.pem not found");
        }
        byte[] keyBytes = is.readAllBytes();
        String pem = new String(keyBytes, StandardCharsets.UTF_8)
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+","");
        byte[] decoded = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    /**
     * Handles the version check request from the device.
     * Reads the version string from firmware/version.txt and returns it as plain text.
     */
    @GetMapping("/version")
    public ResponseEntity<String> getFirmwareVersion() {
        Path path = Paths.get(VERSION_PATH);
        if (!Files.exists(path)) {
            logger.warn("Version file not found: {}", VERSION_PATH);
            return ResponseEntity.notFound().build();
        }

        try {
            String version = Files.readString(path, StandardCharsets.UTF_8).trim();
            logger.info("Serving version: {}", version);
            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_PLAIN)
                    .body(version);
        } catch (IOException e) {
            logger.error("Error reading version file", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/firmware")
    public ResponseEntity<Resource> getEncryptedFirmware() {
        try {
            File enc = new File(FIRMWARE_ENC_PATH);
            File bin = new File(FIRMWARE_BIN_PATH);
            if (!enc.exists()) return ResponseEntity.notFound().build();
            if (!bin.exists()) logger.warn("Plain firmware (for signature size) not found: {}", FIRMWARE_BIN_PATH);

            InputStreamResource resource = new InputStreamResource(new FileInputStream(enc));
            long encLen = enc.length();
            long plainLen = bin.exists() ? bin.length() : -1;

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=firmware.enc")
                    .contentLength(encLen)
                    .header("X-Plain-Size", String.valueOf(plainLen))
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(resource);

        } catch (Exception e) {
            logger.error("Error serving firmware", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/signature")
    public ResponseEntity<String> getSignature() {
        try {
            File bin = new File(FIRMWARE_BIN_PATH);
            if (!bin.exists()) {
                logger.warn("Plain firmware not found for signing: {}", FIRMWARE_BIN_PATH);
                return ResponseEntity.notFound().build();
            }

            PrivateKey pk = loadPrivateKey();

            // Read plain firmware bytes and compute signature over plain bytes (not over the encrypted file)
            byte[] binBytes = Files.readAllBytes(bin.toPath());

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(binBytes);
            logger.info("Signing firmware, SHA256: {}", bytesToHex(hash));

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(pk);
            signature.update(binBytes); // IMPORTANT: pass plaintext bytes
            byte[] sigBytes = signature.sign();

            String base64Sig = Base64.getEncoder().encodeToString(sigBytes);
            return ResponseEntity.ok(base64Sig);
        } catch (Exception e) {
            logger.error("Error generating signature", e);
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }

    // utility hex printer for logs
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}