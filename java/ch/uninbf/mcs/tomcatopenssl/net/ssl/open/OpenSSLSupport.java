/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ch.uninbf.mcs.tomcatopenssl.net.ssl.open;

import java.io.IOException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSession;
import java.net.Socket;
import org.apache.tomcat.util.net.SSLSessionManager;
import org.apache.tomcat.util.net.SSLSupport;

/**
 *
 * @author leo
 */
public class OpenSSLSupport implements SSLSupport, SSLSessionManager {
    
    private OpenSSLSession session;
    private Socket sock;

    public OpenSSLSession getSession() { return session; }
    
    public OpenSSLSupport(SSLSession session) {
        this.session = (OpenSSLSession) session;
    }
    
    public OpenSSLSupport(Socket sock) {
        this.sock = sock;
    }

    @Override
    public String getCipherSuite() throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Integer getKeySize() throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getSessionId() throws IOException {
        if(session == null) {
            return null;
        }
        byte[] session_id = session.getId();
        if(session_id == null) {
            return null;
        }
        return new String(session_id, "UTF-8");
    }

    @Override
    public String getProtocol() throws IOException {
        if(session == null) {
            return null;
        }
        return session.getProtocol();
    }

    @Override
    public void invalidateSession() {
        getSession().invalidate();
    }

    @Override
    public X509Certificate[] getPeerCertificateChain(boolean force) throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
