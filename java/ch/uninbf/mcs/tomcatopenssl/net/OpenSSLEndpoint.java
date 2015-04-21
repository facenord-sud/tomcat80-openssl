/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ch.uninbf.mcs.tomcatopenssl.net;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.Nio2Endpoint;

/**
 *
 * @author Numa de Montmollin <numa.demontmollin@unifr.ch>
 */
public class OpenSSLEndpoint extends Nio2Endpoint{
    
    private static final Log log = LogFactory.getLog(OpenSSLEndpoint.class);
    
    private String certChainFile;
    public void setCertChainFile(String filePath) { this.certChainFile = filePath; }
    public String getCertChainFile() { return certChainFile; }
    
    private String keyFile;
    public void setKeyFile(String filePath) { this.keyFile = filePath; }
    public String getKeyFile() { return keyFile; }
}
