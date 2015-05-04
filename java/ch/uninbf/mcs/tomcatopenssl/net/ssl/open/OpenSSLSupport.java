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
    
    private SSLSession session;
    private Socket sock;

    public OpenSSLSupport(SSLSession session) {
        this.session = session;
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
        session.invalidate();
    }

    @Override
    public X509Certificate[] getPeerCertificateChain(boolean force) throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
