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
package ch.uninbf.mcs.tomcatopenssl.net.ssl.open;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.SSLUtil;
import org.apache.tomcat.util.net.ServerSocketFactory;
import org.apache.tomcat.util.net.SslContext;
import org.apache.tomcat.util.net.jsse.openssl.OpenSSLCipherConfigurationParser;

/**
 *
 * @author leo
 */
public class OpenSSLSocketFactory implements SSLUtil, ServerSocketFactory {

    private final AbstractEndpoint<?> endpoint;

    private static final Log log = LogFactory.getLog(OpenSSLSocketFactory.class);

    private String[] enabledProtocols = null;
    private String[] enabledCiphers = null;

    private static final String CONTEXT_NAME = "ch.uninbf.mcs.tomcatopenssl.net.ssl.open.OpenSSLContext";
    private OpenSSLContext context;

    public OpenSSLSocketFactory(AbstractEndpoint<?> endPoint) {
        this.endpoint = endPoint;
        try { 
            this.context = (OpenSSLContext) SslContext.getInstance(CONTEXT_NAME, endpoint.getSslProtocol());
            this.enabledProtocols = new OpenSSLProtocols(context.getEnabledProtocol()).getProtocols();
            List<String> requestedCiphers = null;
            String requestedCiphersStr = endpoint.getCiphers();
            if (requestedCiphersStr.indexOf(':') != -1) {
                requestedCiphers = OpenSSLCipherConfigurationParser.parseExpression(requestedCiphersStr);
            }
            context.setRequestedCiphers(requestedCiphers);
            context.determineCiphers(requestedCiphers);
            List<String> enabledCiphersList = context.getCiphers();
            this.enabledCiphers = enabledCiphersList.toArray(new String[enabledCiphersList.size()]);
        } catch (ClassNotFoundException ex) {
            log.debug("Unalble to determine ciphers and protcols", ex);
        }
    }

    @Override
    public SslContext createSSLContext() throws Exception {
        context.setSessionTimeout(getSessionConfig(endpoint.getSessionTimeout()));
        context.setSessionCacheSize(getSessionConfig(endpoint.getSessionCacheSize()));
        context.setKeyPassowrd(endpoint.getKeystorePass());
        
        return context;
    }

    private long getSessionConfig(String config) {
        if (config == null) {
            return 0;
        }
        return Long.parseLong(config);
    }

    @Override
    public KeyManager[] getKeyManagers() throws Exception {
        KeyManager[] managers = {new OpenSSLKeyManager(endpoint.getTruststoreFile(), endpoint.getKeystoreFile())};
        return managers;
    }

    @Override
    public TrustManager[] getTrustManagers() throws Exception {
        return null;
    }

    @Override
    public void configureSessionContext(SSLSessionContext sslSessionContext) {
        // do nothing. configuration is done in the init phase
    }

    @Override
    public String[] getEnableableCiphers(SslContext context) {
        return this.enabledCiphers;
    }

    @Override
    public String[] getEnableableProtocols(SslContext context) {
        return this.enabledProtocols;
    }

    @Override
    public ServerSocket createSocket(int port) throws IOException, InstantiationException {
        return null;
    }

    @Override
    public ServerSocket createSocket(int port, int backlog) throws IOException, InstantiationException {
        return null;
    }

    @Override
    public ServerSocket createSocket(int port, int backlog, InetAddress ifAddress) throws IOException, InstantiationException {
        return null;
    }

    @Override
    public Socket acceptSocket(ServerSocket socket) throws IOException {
        return null;
    }

    @Override
    public void handshake(Socket sock) throws IOException {
    }

}
