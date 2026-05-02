package com.fivucsas.identity.infrastructure.web;

import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Simple in-memory {@link MultipartFile} backed by a byte array.
 *
 * <p>Used when an HTTP body provides a base64-encoded image that must be
 * forwarded to a downstream service expecting a multipart upload (e.g. the
 * biometric processor). Centralised here so the same shape is not redefined
 * inline in multiple controllers (was previously copy-pasted as an anonymous
 * inner class in {@code AuthController.verify2FAMethod} alongside an unused
 * private record of the same name — see quality review P1-Q5, 2026-05-01).
 */
public record InMemoryMultipartFile(
        String name, String originalFilename, String contentType, byte[] content
) implements MultipartFile {

    @Override
    public String getName() { return name; }

    @Override
    public String getOriginalFilename() { return originalFilename; }

    @Override
    public String getContentType() { return contentType; }

    @Override
    public boolean isEmpty() { return content == null || content.length == 0; }

    @Override
    public long getSize() { return content != null ? content.length : 0; }

    @Override
    public byte[] getBytes() { return content; }

    @Override
    public InputStream getInputStream() { return new ByteArrayInputStream(content); }

    @Override
    public void transferTo(File dest) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(dest)) {
            fos.write(content);
        }
    }
}
