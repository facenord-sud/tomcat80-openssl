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
