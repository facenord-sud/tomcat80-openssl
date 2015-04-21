package ch.uninbf.mcs.tomcatopenssl.net.ssl.open;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Get SSL protocols in the right preference order
 * 
 * @author Numa de Montmollin <numa.demontmollin@unifr.ch>
 */
public class OpenSSLProtocols {

    private static final List<String> openSSLProtocols = new ArrayList<>();

    public static String[] getProtocols(String preferredJSSE) {
        Collections.addAll(openSSLProtocols, "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3", "SSLv2");
        if(openSSLProtocols.contains(preferredJSSE)) {
            openSSLProtocols.remove(preferredJSSE);
            openSSLProtocols.add(0, preferredJSSE);
        }
        return openSSLProtocols.toArray(new String[openSSLProtocols.size()]);
    }
}
