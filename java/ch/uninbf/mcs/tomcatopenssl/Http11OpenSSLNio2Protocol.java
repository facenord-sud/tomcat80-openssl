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
package ch.uninbf.mcs.tomcatopenssl;

import ch.uninbf.mcs.tomcatopenssl.net.OpenSSLEndpoint;
import org.apache.coyote.http11.Http11Nio2Protocol;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Just for testing, it is the easiest way for starting
 * @author leo
 */
public class Http11OpenSSLNio2Protocol extends Http11Nio2Protocol{
        
    private static final Log log = LogFactory.getLog(Http11Nio2Protocol.class);
    public Http11OpenSSLNio2Protocol() {
        super();
        // will cause trouble, now...
        endpoint = new OpenSSLEndpoint();
        ((OpenSSLEndpoint) endpoint).setHandler((Http11Nio2Protocol.Http11ConnectionHandler) getHandler());
        setSslImplementationName("ch.uninbf.mcs.tomcatopenssl.net.ssl.open.OpenSSLImplementation");
        getEndpoint().setSSLEnabled(true);
        log.error("Hello world! I'm a test");
    }
    
    private OpenSSLEndpoint getOpenSSLEndpoint() {
        return (OpenSSLEndpoint) endpoint;
    }

    @Override
    protected String getNamePrefix() {
        return "http-openssl";
    }
    
    public void setCertChainFile(String filePath) {
        getOpenSSLEndpoint().setCertChainFile(filePath);
    }
    
    public void setKeyFile(String filePath) {
        getOpenSSLEndpoint().setKeyFile(filePath);
    }
}
