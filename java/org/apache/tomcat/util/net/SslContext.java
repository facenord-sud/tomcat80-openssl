/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.apache.tomcat.util.net;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 *
 * @author leo
 */
public abstract class SslContext {
    
    private static final Log logger = LogFactory.getLog(SslContext.class);
    private static final HashMap<String, SslContext> instances = new HashMap<>();
    
    public static SslContext getInstance(String className, String protocol)
            throws ClassNotFoundException {
        if(instances.containsKey(className))
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
            throw new ClassNotFoundException("Error loading SSL Context " + className, e);
        }
    }
    
    public abstract void init(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException;
    public abstract SSLSessionContext getServerSessionContext();
    public abstract SSLEngine createSSLEngine();
    public abstract SSLServerSocketFactory getServerSocketFactory();
    public abstract SSLParameters getSupportedSSLParameters();
    protected abstract void initiateProtocol(String protocol) throws NoSuchAlgorithmException;
}
