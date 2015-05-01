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

package org.apache.tomcat.util.net;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

public abstract class SslContext {

    private static final Log logger = LogFactory.getLog(SslContext.class);
    private static final HashMap<String, SslContext> instances = new HashMap<>();

    public static SslContext getInstance(String className, String protocol)
            throws ClassNotFoundException {
        if (instances.containsKey(className))
            return instances.get(className);
        try {
            Class<?> clazz = Class.forName(className);
            SslContext context = (SslContext) clazz.newInstance();
            context.initiateProtocol(protocol);
            instances.put(className, context);
            return context;
        } catch (Exception e) {
            if (logger.isDebugEnabled())
                logger.debug("Error loading SSL Context " + className, e);
            throw new ClassNotFoundException("Error loading SSL Context "
                    + className, e);
        }
    }

    public abstract void init(KeyManager[] kms, TrustManager[] tms,
            SecureRandom sr) throws SSLException;

    public abstract SSLSessionContext getServerSessionContext();

    public abstract SSLEngine createSSLEngine();

    public abstract SSLServerSocketFactory getServerSocketFactory();

    public abstract SSLParameters getSupportedSSLParameters();

    protected abstract void initiateProtocol(String protocol)
            throws NoSuchAlgorithmException;
}
