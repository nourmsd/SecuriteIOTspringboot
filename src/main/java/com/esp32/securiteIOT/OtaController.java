package com.esp32.securiteIOT;

import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@RestController
public class OtaController {

    // -----------------------------------------------------------------
    //  Configuration (change only these when you release a new build)
    // -----------------------------------------------------------------
    private static final String FIRMWARE_VERSION = "1.0.0";          // bump when new firmware
    private static final String FIRMWARE_PATH    = "firmware/firmware.ino.bin"; // Arduino output
    private static final String PRIVATE_KEY_PATH = "keys/private.pem";

    // -----------------------------------------------------------------
    //  1. Firmware version
    // -----------------------------------------------------------------
    @GetMapping("/ota/version")
    public ResponseEntity<String> getVersion() {
        return ResponseEntity.ok(FIRMWARE_VERSION);
    }

    // -----------------------------------------------------------------
    //  2. Plain firmware binary (for OTA)
    // -----------------------------------------------------------------
    @GetMapping("/ota/firmware")
    public ResponseEntity<Resource> getFirmware() throws IOException {
        File file = new File(FIRMWARE_PATH);
        if (!file.exists()) {
            return ResponseEntity.notFound().build();
        }

        InputStreamResource resource = new InputStreamResource(new FileInputStream(file));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=firmware.bin")
                .contentLength(file.length())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(resource);
    }

    // -----------------------------------------------------------------
    //  3. ECDSA signature of the firmware (SHA256withECDSA)
    // -----------------------------------------------------------------
    @GetMapping("/ota/firmware.sig")
    public ResponseEntity<Resource> getFirmwareSignature() throws Exception {
        PrivateKey privateKey = loadPrivateKey(PRIVATE_KEY_PATH);
        byte[] firmwareBytes = Files.readAllBytes(Paths.get(FIRMWARE_PATH));

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(privateKey);
        ecdsa.update(firmwareBytes);
        byte[] signature = ecdsa.sign();

        // Write to a temporary file (auto-deleted on JVM exit)
        File temp = File.createTempFile("firmware", ".sig");
        Files.write(temp.toPath(), signature);
        temp.deleteOnExit();

        InputStreamResource resource = new InputStreamResource(new FileInputStream(temp));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=firmware.sig")
                .contentLength(signature.length)
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(resource);
    }

    // -----------------------------------------------------------------
    //  Helper: load EC private key from PEM file
    // -----------------------------------------------------------------
    private PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(path));
        String pem = new String(keyBytes)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(spec);
    }
}