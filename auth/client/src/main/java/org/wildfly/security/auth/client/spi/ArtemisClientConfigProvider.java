/*
 * Copyright 2022 JBoss by Red Hat.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.auth.client.spi;

import java.net.URI;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Map;
import javax.net.ssl.SSLContext;
import org.apache.activemq.artemis.api.core.TransportConfiguration;
import org.apache.activemq.artemis.core.remoting.impl.netty.TransportConstants;
import org.apache.activemq.artemis.spi.core.remoting.ssl.SSLContextConfig;
import org.apache.activemq.artemis.spi.core.remoting.ssl.SSLContextFactory;
import org.apache.activemq.artemis.utils.ConfigurationHelper;
import org.kohsuke.MetaInfServices;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;

/**
 *
 * @author Emmanuel Hugonnet (c) 2021 Red Hat, Inc.
 */
@MetaInfServices(value = SSLContextFactory.class)
public class ArtemisClientConfigProvider implements SSLContextFactory {

    static final AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT = AccessController.doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);

    @Override
    public SSLContext getSSLContext(SSLContextConfig config, Map<String, Object> configuration) throws Exception {
        String host = ConfigurationHelper.getStringProperty(TransportConstants.HOST_PROP_NAME, TransportConstants.DEFAULT_HOST, configuration);
        int port = ConfigurationHelper.getIntProperty(TransportConstants.PORT_PROP_NAME, TransportConstants.DEFAULT_PORT, configuration);
        URI uri = new URI("artemis://" + host + ":" + port + TransportConfiguration.toStringParameters(configuration, null));
        return AUTH_CONTEXT_CLIENT.getSSLContext(uri, AuthenticationContext.captureCurrent());
    }

    @Override
    public int getPriority() {
        return 15;
    }

}
