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

@RestController
public class OtaController {

    // Current firmware version
    private static final String FIRMWARE_VERSION = "1.0.0"; // change to new version

    // Path to the firmware file
    private static final String FIRMWARE_PATH = "firmware/firmware.bin";

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
}