package ch.uninbf.mcs.tomcatopenssl.net.ssl.open;

import java.io.File;
import javax.net.ssl.KeyManager;

/**
 *
 * @author Numa de Montmollin <numa.demontmollin@unifr.ch>
 */
public class OpenSSLKeyManager implements KeyManager{

    private File certificateChain;
    public File getCertificateChain() { return certificateChain; }
    public void setCertificateChain(File certificateChain) { this.certificateChain = certificateChain; }
    
    private File privateKey;
    public File getPrivateKey() { return privateKey; }
    public void setPrivateKey(File privateKey) { this.privateKey = privateKey; }
    
    OpenSSLKeyManager(String certChainFile, String keyFile) {
        if (certChainFile == null) {
            throw new IllegalArgumentException("Null certChainFile");
        }
        if (keyFile == null) {
            throw new IllegalArgumentException("Null keyFile");
        }
        this.certificateChain = new File(certChainFile);
        this.privateKey = new File(keyFile);
    }
    
}
