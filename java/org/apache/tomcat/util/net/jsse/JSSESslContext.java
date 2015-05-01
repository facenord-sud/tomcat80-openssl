/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.tomcat.util.net.jsse;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.SslContext;

public class JSSESslContext extends SslContext {

    private SSLContext context;
    private static final Log logger = LogFactory.getLog(JSSESslContext.class);

    @Override
    public void init(KeyManager[] kms, TrustManager[] tms, SecureRandom sr)
            throws SSLException {
        try {
            context.init(kms, tms, sr);
        } catch (KeyManagementException e) {
           throw new SSLException("Failed to initialize the JSSESslContext. A problem with the key manager occured.", e);
        }
    }

    @Override
    public SSLSessionContext getServerSessionContext() {
        return context.getServerSessionContext();
    }

    @Override
    public SSLEngine createSSLEngine() {
        return context.createSSLEngine();
    }

    @Override
    public SSLServerSocketFactory getServerSocketFactory() {
        return context.getServerSocketFactory();
    }

    @Override
    public SSLParameters getSupportedSSLParameters() {
        return context.getSupportedSSLParameters();
    }

    @Override
    protected void initiateProtocol(String protocol)
            throws NoSuchAlgorithmException {
        context = SSLContext.getInstance(protocol);
    }

}
