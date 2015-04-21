/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.apache.tomcat.util.net.jsse;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.SSLContext;
import org.apache.tomcat.util.net.SslContext;

/**
 *
 * @author leo
 */
public class JSSESslContext extends SslContext{

    private SSLContext context;
    
    @Override
    public void init(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        context.init(kms, tms, sr);
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
    protected void initiateProtocol(String protocol) throws NoSuchAlgorithmException {
        context = SSLContext.getInstance(protocol);
    }
    
}
