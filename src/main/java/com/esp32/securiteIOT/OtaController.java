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


    private static final String FIRMWARE_VERSION = "1.0.0";
    private static final String FIRMWARE_PATH = "firmware/firmware.ino.bin";
    private static final String PRIVATE_KEY_PATH = "keys/private.pem";
    /**
     * Endpoint to return current firmware version
     */
    @GetMapping("/ota/version")
    public ResponseEntity<String> getVersion() {
        return ResponseEntity.ok(FIRMWARE_VERSION);
    }

    /**
     * Endpoint to download the firmware binary
     */
    @GetMapping("/ota/firmware")
    public ResponseEntity<Resource> getFirmware() throws IOException {
        File file = new File(FIRMWARE_PATH);
        if (!file.exists()) return ResponseEntity.notFound().build();

        InputStreamResource resource = new InputStreamResource(new FileInputStream(file));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=firmware.bin")
                .contentLength(file.length())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(resource);
    }
    // --- 3️⃣ Signature endpoint ---
    @GetMapping("/ota/firmware.sig")
    public ResponseEntity<Resource> getFirmwareSignature() throws Exception {
        // Load private key
        PrivateKey privateKey = loadPrivateKey(PRIVATE_KEY_PATH);

        // Read firmware bytes
        byte[] firmwareBytes = Files.readAllBytes(Paths.get(FIRMWARE_PATH));

        // Compute SHA-256 and sign
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(firmwareBytes); // You can sign firmware bytes directly
        byte[] signatureBytes = ecdsaSign.sign();

        // Save signature to temporary file
        File tempSig = File.createTempFile("firmware", ".sig");
        Files.write(tempSig.toPath(), signatureBytes);

        InputStreamResource resource = new InputStreamResource(new FileInputStream(tempSig));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=firmware.sig")
                .contentLength(signatureBytes.length)
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(resource);
    }

    // --- Helper: load private key from PEM ---
    private PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(path));
        String keyPEM = new String(keyBytes)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(keyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(spec);
    }
}



