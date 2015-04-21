/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ch.uninbf.mcs.tomcatopenssl.net.ssl.open;

import ch.uninbf.mcs.tomcatopenssl.net.OpenSSLEndpoint;
import static ch.uninbf.mcs.tomcatopenssl.net.ssl.open.OpenSSLContext.generateKeySpec;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.Constants;
import org.apache.tomcat.util.net.SSLUtil;
import org.apache.tomcat.util.net.ServerSocketFactory;
import org.apache.tomcat.util.net.SslContext;
import org.apache.tomcat.util.net.jsse.JSSEKeyManager;
import static org.apache.tomcat.util.net.jsse.JSSESocketFactory.DEFAULT_KEY_PASS;
import org.apache.tomcat.util.net.jsse.openssl.OpenSSLCipherConfigurationParser;
import org.apache.tomcat.util.res.StringManager;

/**
 *
 * @author leo
 */
public class OpenSSLSocketFactory implements SSLUtil, ServerSocketFactory {

    private final AbstractEndpoint<?> endpoint;

    public OpenSSLEndpoint getEndpoint() {
        return (OpenSSLEndpoint) endpoint;
    }
    private static final Log log = LogFactory.getLog(OpenSSLSocketFactory.class);

    private static final String defaultKeystoreFile
            = System.getProperty("user.home") + "/.keystore";
    private TrustManagerFactory trustManagerFactory;
    private String[] enabledProtocols = null;
    private String[] enabledCiphers = null;

    private static final String CONTEXT_NAME = "ch.uninbf.mcs.tomcatopenssl.net.ssl.open.OpenSSLContext";

    public OpenSSLSocketFactory(AbstractEndpoint<?> endPoint) {
        this.endpoint = endPoint;
        try { 
            OpenSSLContext context = (OpenSSLContext) SslContext.getInstance(CONTEXT_NAME, endpoint.getSslProtocol());
            this.enabledProtocols = OpenSSLProtocols.getProtocols(context.getEnabledProtocol());
            List<String> requestedCiphers = null;
            String requestedCiphersStr = endpoint.getCiphers();
            if (requestedCiphersStr.indexOf(':') != -1) {
                requestedCiphers = OpenSSLCipherConfigurationParser.parseExpression(requestedCiphersStr);
            }
            context.setRequestedCiphers(requestedCiphers);
            context.determineCiphers(requestedCiphers);
            List<String> enabledCiphers = context.getCiphers();
            this.enabledCiphers = enabledCiphers.toArray(new String[enabledCiphers.size()]);
        } catch (ClassNotFoundException ex) {
            log.debug("Unalble to determine ciphers and protcols");
        }
    }

    @Override
    public SslContext createSSLContext() throws Exception {
        OpenSSLContext context = (OpenSSLContext) SslContext.getInstance(CONTEXT_NAME, endpoint.getSslProtocol());
        context.setSessionTimeout(getSessionConfig(endpoint.getSessionTimeout()));
        context.setSessionCacheSize(getSessionConfig(endpoint.getSessionCacheSize()));

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
        KeyManager[] managers = {new OpenSSLKeyManager(getEndpoint().getCertChainFile(), getEndpoint().getKeyFile())};
        return managers;
//        String keystoreType = endpoint.getKeystoreType();
//        if (keystoreType == null) {
//            keystoreType = defaultKeystoreType;
//        }
//
//        String algorithm = endpoint.getAlgorithm();
//        if (algorithm == null) {
//            algorithm = KeyManagerFactory.getDefaultAlgorithm();
//        }
//
//        return getKeyManagers(keystoreType, endpoint.getKeystoreProvider(),
//                algorithm, endpoint.getKeyAlias());
    }

    private void checkFileExists(File file) throws IOException {
        if (!file.exists()) {
            log.error("The file " + file + " do not exists");
            throw new FileNotFoundException();
        }
    }

//    /**
//     * Gets the initialized key managers.
//     */
//    private KeyManager[] getKeyManagers(String keystoreType,
//                                          String keystoreProvider,
//                                          String algorithm,
//                                          String keyAlias)
//                throws Exception {
//
//        KeyManager[] kms = null;
//
//        String keystorePass = getKeystorePassword();
//
//        KeyStore ks = getKeystore(keystoreType, keystoreProvider, keystorePass);
//        if (keyAlias != null && !ks.isKeyEntry(keyAlias)) {
//            throw new IOException(
//                    sm.getString("jsse.alias_no_key_entry", keyAlias));
//        }
//
//        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
//        String keyPass = endpoint.getKeyPass();
//        if (keyPass == null) {
//            keyPass = keystorePass;
//        }
//        kmf.init(ks, keyPass.toCharArray());
//
//        kms = kmf.getKeyManagers();
//        if (keyAlias != null) {
//            String alias = keyAlias;
//            if ("JKS".equals(keystoreType)) {
//                alias = alias.toLowerCase(Locale.ENGLISH);
//            }
//            for(int i=0; i<kms.length; i++) {
//                kms[i] = new JSSEKeyManager((X509KeyManager)kms[i], alias);
//            }
//        }
//
//        return kms;
//    }
//    
//    /*
//     * Gets the SSL server's keystore password.
//     */
//    protected String getKeystorePassword() {
//        String keystorePass = endpoint.getKeystorePass();
//        if (keystorePass == null) {
//            keystorePass = endpoint.getKeyPass();
//        }
//        if (keystorePass == null) {
//            keystorePass = DEFAULT_KEY_PASS;
//        }
//        return keystorePass;
//    }
//    
//    /*
//     * Gets the SSL server's keystore.
//     */
//    protected KeyStore getKeystore(String type, String provider, String pass)
//            throws IOException {
//
//        String keystoreFile = endpoint.getKeystoreFile();
//        if (keystoreFile == null)
//            keystoreFile = defaultKeystoreFile;
//
//        return getStore(type, provider, keystoreFile, pass);
//    }
//    
//    private KeyStore getStore(String type, String provider, String path,
//            String pass) throws IOException {
//
//        KeyStore ks = null;
//        InputStream istream = null;
//        try {
//            if (provider == null) {
//                ks = KeyStore.getInstance(type);
//            } else {
//                ks = KeyStore.getInstance(type, provider);
//            }
//            if(!("PKCS11".equalsIgnoreCase(type) ||
//                    "".equalsIgnoreCase(path))) {
//                File keyStoreFile = new File(path);
//                if (!keyStoreFile.isAbsolute()) {
//                    keyStoreFile = new File(System.getProperty(
//                            Constants.CATALINA_BASE_PROP), path);
//                }
//                istream = new FileInputStream(keyStoreFile);
//            }
//
//            char[] storePass = null;
//            if (pass != null && !"".equals(pass)) {
//                storePass = pass.toCharArray();
//            }
//            ks.load(istream, storePass);
//        } catch (FileNotFoundException fnfe) {
//            log.error(sm.getString("jsse.keystore_load_failed", type, path,
//                    fnfe.getMessage()), fnfe);
//            throw fnfe;
//        } catch (IOException ioe) {
//            // May be expected when working with a trust store
//            // Re-throw. Caller will catch and log as required
//            throw ioe;
//        } catch(Exception ex) {
//            String msg = sm.getString("jsse.keystore_load_failed", type, path,
//                    ex.getMessage());
//            log.error(msg, ex);
//            throw new IOException(msg);
//        } finally {
//            if (istream != null) {
//                try {
//                    istream.close();
//                } catch (IOException ioe) {
//                    // Do nothing
//                }
//            }
//        }
//
//        return ks;
//    }
    @Override
    public TrustManager[] getTrustManagers() throws Exception {
//        try {
//            OpenSSLKeyManager keyManager = OpenSSLContext.chooseKeyManager(getKeyManagers());
//            File keyFile = keyManager.getPrivateKey();
//            File certChainFile = keyManager.getCertificateChain();
//            KeyStore ks = KeyStore.getInstance("JKS");
//            
//            ks.load(null, null);
//            CertificateFactory cf = CertificateFactory.getInstance("X.509");
//            KeyFactory rsaKF = KeyFactory.getInstance("RSA");
//            KeyFactory dsaKF = KeyFactory.getInstance("DSA");
//
//            char[] keyPasswordChars = getKeystorePassword().toCharArray();
//            PKCS8EncodedKeySpec encodedKeySpec = generateKeySpec(keyPasswordChars, PemReader.readPrivateKey(keyFile));
//
//            PrivateKey key;
//            try {
//                key = rsaKF.generatePrivate(encodedKeySpec);
//            } catch (InvalidKeySpecException ignore) {
//                key = dsaKF.generatePrivate(encodedKeySpec);
//            }
//
//            List<Certificate> certChain = new ArrayList<>();
//            ByteBuffer[] certs = PemReader.readCertificates(certChainFile);
//
//            for (ByteBuffer buf : certs) {
//                if (buf.hasArray()) {
//                    throw new Exception("unable to read the content of the certificate");
//                }
//                certChain.add(cf.generateCertificate(new ByteArrayInputStream(buf.array())));
//            }
//
//            ks.setKeyEntry("key", key, keyPasswordChars, certChain.toArray(new Certificate[certChain.size()]));
//
//            if (trustManagerFactory == null) {
//                // Mimic the way SSLContext.getInstance(KeyManager[], null, null) works
//                trustManagerFactory = TrustManagerFactory.getInstance(
//                        TrustManagerFactory.getDefaultAlgorithm());
//                trustManagerFactory.init((KeyStore) null);
//            } else {
//                trustManagerFactory.init(ks);
//            }
//        } catch (Exception e) {
//            log.error("Failed to set up trustManagers: ", e);
//            throw e;
//        }
//        return trustManagerFactory.getTrustManagers();
        return null;
    }

    protected String getKeystorePassword() {
        String keystorePass = endpoint.getKeystorePass();
        if (keystorePass == null) {
            keystorePass = endpoint.getKeyPass();
        }
        if (keystorePass == null) {
            keystorePass = DEFAULT_KEY_PASS;
        }
        return keystorePass;
    }

    @Override
    public void configureSessionContext(SSLSessionContext sslSessionContext) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
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
