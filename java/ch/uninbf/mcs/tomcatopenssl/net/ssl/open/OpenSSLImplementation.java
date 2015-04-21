/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ch.uninbf.mcs.tomcatopenssl.net.ssl.open;

import java.net.Socket;
import javax.net.ssl.SSLSession;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.SSLImplementation;
import org.apache.tomcat.util.net.SSLSupport;
import org.apache.tomcat.util.net.SSLUtil;
import org.apache.tomcat.util.net.ServerSocketFactory;

/**
 *
 * @author leo
 */
public class OpenSSLImplementation extends SSLImplementation{

    @Override
    public String getImplementationName() {
        return "OpenSSl";
    }

    @Override
    public ServerSocketFactory getServerSocketFactory(AbstractEndpoint<?> endpoint) {
        return new OpenSSLSocketFactory(endpoint);
    }

    @Override
    public SSLSupport getSSLSupport(Socket sock) {
        return new OpenSSLSupport(sock);
    }

    @Override
    public SSLSupport getSSLSupport(SSLSession session) {
        return new OpenSSLSupport(session);
    }

    @Override
    public SSLUtil getSSLUtil(AbstractEndpoint<?> ep) {
        return new OpenSSLSocketFactory(ep);
    }

    
}
