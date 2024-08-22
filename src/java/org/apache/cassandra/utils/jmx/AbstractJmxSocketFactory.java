/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.cassandra.utils.jmx;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLException;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.cassandra.config.EncryptionOptions;

import static org.apache.cassandra.config.CassandraRelevantProperties.COM_SUN_MANAGEMENT_JMXREMOTE_SSL;
import static org.apache.cassandra.config.CassandraRelevantProperties.COM_SUN_MANAGEMENT_JMXREMOTE_SSL_ENABLED_CIPHER_SUITES;
import static org.apache.cassandra.config.CassandraRelevantProperties.COM_SUN_MANAGEMENT_JMXREMOTE_SSL_ENABLED_PROTOCOLS;
import static org.apache.cassandra.config.CassandraRelevantProperties.COM_SUN_MANAGEMENT_JMXREMOTE_SSL_NEED_CLIENT_AUTH;
import static org.apache.cassandra.config.CassandraRelevantProperties.JAVAX_RMI_SSL_CLIENT_ENABLED_CIPHER_SUITES;
import static org.apache.cassandra.config.CassandraRelevantProperties.JAVAX_RMI_SSL_CLIENT_ENABLED_PROTOCOLS;

abstract public class AbstractJmxSocketFactory implements IJmxSocketFactory
{
    private static final Logger logger = LoggerFactory.getLogger(AbstractJmxSocketFactory.class);

    @Override
    public Map<String, Object> configure(InetAddress serverAddress, boolean localOnly,
                                         EncryptionOptions jmxEncryptionOptions) throws SSLException
    {
        Map<String, Object> env = new HashMap<>();
        if (COM_SUN_MANAGEMENT_JMXREMOTE_SSL.getBoolean())
        {
            logger.info("Enabling JMX SSL using environment file properties");
            logger.warn("Consider using the jmx_encryption_options section of cassandra.yaml instead to prevent " +
                        "sensitive information being exposed");
            boolean requireClientAuth = COM_SUN_MANAGEMENT_JMXREMOTE_SSL_NEED_CLIENT_AUTH.getBoolean();
            String[] protocols = null;
            String protocolList = COM_SUN_MANAGEMENT_JMXREMOTE_SSL_ENABLED_PROTOCOLS.getString();
            if (protocolList != null)
            {
                JAVAX_RMI_SSL_CLIENT_ENABLED_PROTOCOLS.setString(protocolList);
                protocols = StringUtils.split(protocolList, ',');
            }

            String[] ciphers = null;
            String cipherList = COM_SUN_MANAGEMENT_JMXREMOTE_SSL_ENABLED_CIPHER_SUITES.getString();
            if (cipherList != null)
            {
                JAVAX_RMI_SSL_CLIENT_ENABLED_CIPHER_SUITES.setString(cipherList);
                ciphers = StringUtils.split(cipherList, ',');
            }

            configureClientSocketFactory(env, serverAddress);
            configureServerSocketFactory(env, serverAddress, ciphers, protocols, requireClientAuth);
        }
        else if (jmxEncryptionOptions != null && jmxEncryptionOptions.getEnabled() != null
                 && jmxEncryptionOptions.getEnabled())
        {
            logger.info("Enabling JMX SSL using jmx_encryption_options from cassandra.yaml");
            // Here we can continue to use the SslRMIClientSocketFactory for client sockets.
            // However, we should still set System properties for cipher_suites and enabled_protocols
            // to have the same behavior as cassandra-env.sh based JMX SSL settings
            setJmxSystemProperties(jmxEncryptionOptions);
            configureClientSocketFactory(env, serverAddress);
            configureServerSocketFactory(env, serverAddress, jmxEncryptionOptions);
        }
        else if (localOnly)
        {
            configureLocalSocketFactory(env,serverAddress);
        }

        return env;
    }

    abstract public void configureLocalSocketFactory(Map<String, Object> env, InetAddress serverAddress);

    abstract public void configureClientSocketFactory(Map<String, Object> env, InetAddress serverAddress);

    abstract public void configureServerSocketFactory(Map<String, Object> env, InetAddress serverAddress,
                                                      String[] enabledCipherSuites, String[] enabledProtocols,
                                                      boolean needClientAuth);

    abstract public void configureServerSocketFactory(Map<String, Object> env, InetAddress serverAddress,
                                                      EncryptionOptions jmxEncryptionOptions) throws SSLException;

    void setJmxSystemProperties(EncryptionOptions jmxEncryptionOptions)
    {
        COM_SUN_MANAGEMENT_JMXREMOTE_SSL.setBoolean(true);
        if (jmxEncryptionOptions.getAcceptedProtocols() != null)
        {
            JAVAX_RMI_SSL_CLIENT_ENABLED_PROTOCOLS.setString(StringUtils.join(jmxEncryptionOptions.getAcceptedProtocols(), ","));
        }
        if (jmxEncryptionOptions.cipherSuitesArray() != null)
        {
            JAVAX_RMI_SSL_CLIENT_ENABLED_CIPHER_SUITES.setString(StringUtils.join(jmxEncryptionOptions.cipherSuitesArray(), ","));
        }
    }
}
