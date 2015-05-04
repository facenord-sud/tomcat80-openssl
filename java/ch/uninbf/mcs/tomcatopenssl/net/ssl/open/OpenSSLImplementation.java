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
public class OpenSSLImplementation extends SSLImplementation {

    public static final String IMPLEMENTATION_NAME = "ch.uninbf.mcs.tomcatopenssl.net.ssl.open.OpenSSLImplementation";

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
