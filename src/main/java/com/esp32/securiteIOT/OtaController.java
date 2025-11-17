package com.esp32.securiteIOT;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@RestController
public class OtaController {
    
    private static final String FIRMWARE_PATH = "firmware/firmware.enc";
    private static final String VERSION_PATH = "firmware/version.txt";

    // --------------------------
    // HELPER: read version file
    // --------------------------
    private String readVersion() {
        File f = new File(VERSION_PATH);
        if (!f.exists()) return "1.0";
        try {
            return new String(java.nio.file.Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            return "1.0";
        }
    }

    // --------------------------
    // PUBLIC: ESP32 uses this WITHOUT KEY
    // --------------------------
    @GetMapping("/ota/version")
    public ResponseEntity<String> getVersion(
            @RequestParam(name = "current", required = false) String currentVersion) {

        String serverVersion = readVersion();

        if (currentVersion == null) {
            return ResponseEntity.badRequest().body("Missing current version");
        }

        if (currentVersion.trim().equals(serverVersion.trim())) {
            return ResponseEntity.ok("UP_TO_DATE");
        }

        return ResponseEntity.ok(serverVersion);
    }

    // --------------------------
    // PROTECTED: /ota/firmware
    // --------------------------
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

    private PrivateKey loadPrivateKey(String filePath) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(filePath)))
                .replaceAll("-----\\w+ PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
    // --------------------------
    // PROTECTED: /ota/signature
    // --------------------------
    @GetMapping("/ota/signature")
    public ResponseEntity<String> getSignature() {
        try {
            File fw = new File(FIRMWARE_PATH);
            if (!fw.exists()) return ResponseEntity.notFound().build();

            byte[] firmwareBytes = Files.readAllBytes(fw.toPath());

            Signature signature = Signature.getInstance("SHA256withRSA");
            PrivateKey privateKey = loadPrivateKey("PrivateKey/private.pem"); // path inside your project
            signature.initSign(privateKey);
            signature.update(firmwareBytes);

            byte[] sigBytes = signature.sign();
            String base64Sig = Base64.getEncoder().encodeToString(sigBytes);

            return ResponseEntity.ok(base64Sig);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("");
        }
    }
}
