/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.netty.handler.ssl;

import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.SSL;
import org.apache.tomcat.jni.SSLContext;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import org.apache.catalina.core.AprLifecycleListener;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Tells if <a href="http://netty.io/wiki/forked-tomcat-native.html">{@code netty-tcnative}</a> and its OpenSSL support
 * are available.
 */
public final class OpenSsl {

    private static final Log logger = LogFactory.getLog(OpenSsl.class);
    private static final Throwable UNAVAILABILITY_CAUSE;

    private static final Set<String> AVAILABLE_CIPHER_SUITES;

    static {
        Throwable cause = null;

        // Test if netty-tcnative is in the classpath first.
        try {
            Class.forName("org.apache.tomcat.jni.SSL", false, OpenSsl.class.getClassLoader());
        } catch (ClassNotFoundException t) {
            cause = t;
            logger.debug(
                    "netty-tcnative not in the classpath; OpenSSLEngine will be unavailable.");
        }
        
        if(!AprLifecycleListener.isAprAvailable()) {
            cause = new UnsatisfiedLinkError("APR failed to initialize OpenSSL. Check the logs");
        }
        
        UNAVAILABILITY_CAUSE = cause;

        if (cause == null) {
            final Set<String> availableCipherSuites = new LinkedHashSet<String>(128);
            final long aprPool = Pool.create(0);
            try {
                final long sslCtx = SSLContext.make(aprPool, SSL.SSL_PROTOCOL_ALL, SSL.SSL_MODE_SERVER);
                try {
                    SSLContext.setOptions(sslCtx, SSL.SSL_OP_ALL);
                    SSLContext.setCipherSuite(sslCtx, "ALL");
                    final long ssl = SSL.newSSL(sslCtx, true);
                    try {
                        for (String c: SSL.getCiphers(ssl)) {
                            // Filter out bad input.
                            if (c == null || c.length() == 0 || availableCipherSuites.contains(c)) {
                                continue;
                            }
                            availableCipherSuites.add(c);
                        }
                    } finally {
                        SSL.freeSSL(ssl);
                    }
                } finally {
                    SSLContext.free(sslCtx);
                }
            } catch (Exception e) {
                logger.warn("Failed to get the list of available OpenSSL cipher suites.", e);
            } finally {
                Pool.destroy(aprPool);
            }

            AVAILABLE_CIPHER_SUITES = Collections.unmodifiableSet(availableCipherSuites);
        } else {
            AVAILABLE_CIPHER_SUITES = Collections.emptySet();
        }
    }

    /**
     * Returns {@code true} if and only if
     * <a href="http://netty.io/wiki/forked-tomcat-native.html">{@code netty-tcnative}</a> and its OpenSSL support
     * are available.
     */
    public static boolean isAvailable() {
        return UNAVAILABILITY_CAUSE == null;
    }

    /**
     * Ensure that <a href="http://netty.io/wiki/forked-tomcat-native.html">{@code netty-tcnative}</a> and
     * its OpenSSL support are available.
     *
     * @throws UnsatisfiedLinkError if unavailable
     */
    public static void ensureAvailability() {
        if (UNAVAILABILITY_CAUSE != null) {
            throw (Error) new UnsatisfiedLinkError(
                    "failed to load the required native library").initCause(UNAVAILABILITY_CAUSE);
        }
    }

    /**
     * Returns the cause of unavailability of
     * <a href="http://netty.io/wiki/forked-tomcat-native.html">{@code netty-tcnative}</a> and its OpenSSL support.
     *
     * @return the cause if unavailable. {@code null} if available.
     */
    public static Throwable unavailabilityCause() {
        return UNAVAILABILITY_CAUSE;
    }

    /**
     * Returns all the available OpenSSL cipher suites.
     * Please note that the returned array may include the cipher suites that are insecure or non-functional.
     */
    public static Set<String> availableCipherSuites() {
        return AVAILABLE_CIPHER_SUITES;
    }

    /**
     * Returns {@code true} if and only if the specified cipher suite is available in OpenSSL.
     * Both Java-style cipher suite and OpenSSL-style cipher suite are accepted.
     */
    public static boolean isCipherSuiteAvailable(String cipherSuite) {
        String converted = CipherSuiteConverter.toOpenSsl(cipherSuite);
        if (converted != null) {
            cipherSuite = converted;
        }
        return AVAILABLE_CIPHER_SUITES.contains(cipherSuite);
    }

    public static boolean isError(long errorCode) {
        return errorCode != SSL.SSL_ERROR_NONE;
    }

    private OpenSsl() { }
}
