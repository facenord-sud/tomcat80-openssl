/*
 * Copyright 2014 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package ch.uninbf.mcs.tomcatopenssl.net.ssl.open;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.codec.binary.Base64;

/**
 * Reads a PEM file and converts it into a list of DERs so that they are
 * imported into a {@link KeyStore} easily.
 */
final class PemReader {

    private static final Log logger = LogFactory.getLog(PemReader.class);

    private static final Pattern CERT_PATTERN = Pattern.compile(
            "-+BEGIN\\s+.*CERTIFICATE[^-]*-+(?:\\s|\\r|\\n)+" + // Header
            "([a-z0-9+/=\\r\\n]+)" + // Base64 text
            "-+END\\s+.*CERTIFICATE[^-]*-+", // Footer
            Pattern.CASE_INSENSITIVE);
    private static final Pattern KEY_PATTERN = Pattern.compile(
            "-+BEGIN\\s+.*PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+" + // Header
            "([a-z0-9+/=\\r\\n]+)" + // Base64 text
            "-+END\\s+.*PRIVATE\\s+KEY[^-]*-+", // Footer
            Pattern.CASE_INSENSITIVE);

    static ByteBuffer[] readCertificates(File file) throws CertificateException {
        String content;
        try {
            content = readContent(file);
        } catch (IOException e) {
            throw new CertificateException("failed to read a file: " + file, e);
        }

        List<ByteBuffer> certs = new ArrayList<>();
        Matcher m = CERT_PATTERN.matcher(content);
        int start = 0;
        for (;;) {
            if (!m.find(start)) {
                break;
            }

            certs.add(decodeBase64(m.group(1)));

            start = m.end();
        }

        if (certs.isEmpty()) {
            throw new CertificateException("found no certificates: " + file);
        }

        return certs.toArray(new ByteBuffer[certs.size()]);
    }

    private static ByteBuffer decodeBase64(String decoding) {
        ByteBuffer base64 = ByteBuffer.wrap(decoding.getBytes(Charset.forName("US-ASCII")));
        return java.util.Base64.getDecoder().decode(base64);
    }

    static byte[] readPrivateKey(File file) throws KeyException {
        String content;
        try {
            content = readContent(file);
        } catch (IOException e) {
            throw new KeyException("failed to read a file: " + file, e);
        }

        Matcher m = KEY_PATTERN.matcher(content);
        if (!m.find()) {
            throw new KeyException("found no private key: " + file);
        }

        try {
            byte[] base64 = m.group(1).getBytes(Charset.forName("US-ASCII"));
            return Base64.decodeBase64(base64);
//            return base64;
        } catch (IllegalArgumentException e) {
            throw new KeyException("Failed to decode the key", e);
        }
    }

    private static String readContent(File file) throws IOException {
        InputStream in = new FileInputStream(file);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            byte[] buf = new byte[8192];
            for (;;) {
                int ret = in.read(buf);
                if (ret < 0) {
                    break;
                }
                out.write(buf, 0, ret);
            }
            return out.toString("US-ASCII");
        } finally {
            safeClose(in);
            safeClose(out);
        }
    }

    private static void safeClose(InputStream in) {
        try {
            in.close();
        } catch (IOException e) {
            logger.warn("Failed to close a stream.", e);
        }
    }

    private static void safeClose(OutputStream out) {
        try {
            out.close();
        } catch (IOException e) {
            logger.warn("Failed to close a stream.", e);
        }
    }

    private PemReader() {
    }
}
