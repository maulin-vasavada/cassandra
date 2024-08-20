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

package org.apache.cassandra.distributed.test;

import java.io.IOException;
import java.io.Serializable;
import java.net.Socket;
import java.rmi.server.RMIClientSocketFactory;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.net.SocketFactory;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;

import com.google.common.collect.ImmutableMap;
import org.junit.After;
import org.junit.Test;

import org.apache.cassandra.config.EncryptionOptions;
import org.apache.cassandra.distributed.Cluster;
import org.apache.cassandra.distributed.api.Feature;
import org.apache.cassandra.distributed.test.jmx.JMXGetterCheckTest;
import org.apache.cassandra.transport.TlsTestUtils;

import static org.apache.cassandra.config.CassandraRelevantProperties.COM_SUN_MANAGEMENT_JMXREMOTE_SSL;
import static org.apache.cassandra.config.CassandraRelevantProperties.COM_SUN_MANAGEMENT_JMXREMOTE_SSL_ENABLED_CIPHER_SUITES;
import static org.apache.cassandra.config.CassandraRelevantProperties.COM_SUN_MANAGEMENT_JMXREMOTE_SSL_ENABLED_PROTOCOLS;
import static org.apache.cassandra.config.CassandraRelevantProperties.COM_SUN_MANAGEMENT_JMXREMOTE_SSL_NEED_CLIENT_AUTH;
import static org.apache.cassandra.config.CassandraRelevantProperties.JAVAX_RMI_SSL_CLIENT_ENABLED_CIPHER_SUITES;
import static org.apache.cassandra.config.CassandraRelevantProperties.JAVAX_RMI_SSL_CLIENT_ENABLED_PROTOCOLS;

public class JMXEncryptionOptionsTest extends AbstractEncryptionOptionsImpl
{
    @After
    public void resetJmxSslSystemProperties()
    {
        COM_SUN_MANAGEMENT_JMXREMOTE_SSL.reset();
        COM_SUN_MANAGEMENT_JMXREMOTE_SSL_NEED_CLIENT_AUTH.reset();
        COM_SUN_MANAGEMENT_JMXREMOTE_SSL_ENABLED_PROTOCOLS.reset();
        COM_SUN_MANAGEMENT_JMXREMOTE_SSL_ENABLED_CIPHER_SUITES.reset();
        JAVAX_RMI_SSL_CLIENT_ENABLED_PROTOCOLS.reset();
        JAVAX_RMI_SSL_CLIENT_ENABLED_CIPHER_SUITES.reset();
    }

    @Test
    public void testDefaultSettings() throws Throwable
    {
        System.setProperty("javax.net.ssl.trustStore", (String)validKeystore.get("truststore"));
        try (Cluster cluster = builder().withNodes(1).withConfig(c -> {
            c.with(Feature.JMX);
            c.set("jmx_encryption_options",
                  ImmutableMap.builder().putAll(validKeystore)
                              .put("enabled", true)
                              .put("require_client_auth", false)
                              .put("accepted_protocols", Arrays.asList("TLSv1.2", "TLSv1.3", "TLSv1.1"))
                              .build());
        }).start())
        {
            // Invoke the same code vs duplicating any code from the JMXGetterCheckTest
            JMXGetterCheckTest.testAllValidGetters(cluster);
        }
    }

    @Test
    public void testPEMBasedEncryptionOptions() throws Throwable
    {
        try (Cluster cluster = builder().withNodes(1).withConfig(c -> {
            c.with(Feature.JMX);
            c.set("jmx_encryption_options",
                  ImmutableMap.builder().putAll(validPEMKeystore)
                              .put("enabled", true)
                              .put("require_client_auth", false)
                              .build());
        }).start())
        {
            // Invoke the same code vs duplicating any code from the JMXGetterCheckTest
            JMXGetterCheckTest.testAllValidGetters(cluster);
        }
    }

    @Test
    public void testInvalidKeystorePath() throws Throwable
    {
        try(Cluster cluster = builder().withNodes(1).withConfig(c -> {
            c.with(Feature.JMX);
            c.set("jmx_encryption_options",
                  ImmutableMap.builder()
                              .put("enabled", true)
                              .put("keystore", "/path/to/bad/keystore/that/should/not/exist")
                              .put("keystore_password", "cassandra")
                              .build());
        }).createWithoutStarting())
        {
            assertCannotStartDueToConfigurationException(cluster);
        }
    }

    /**
     * Tests {@code disabled} jmx_encryption_options. Here even if the configured {@code keystore} is invalid, it will
     * not matter and the JMX server/client will start.
     */
    @Test
    public void testDisabledEncryptionOptions() throws Throwable
    {
        try(Cluster cluster = builder().withNodes(1).withConfig(c -> {
            c.with(Feature.JMX);
            c.set("jmx_encryption_options",
                  ImmutableMap.builder()
                              .put("enabled", false)
                              .put("keystore", "/path/to/bad/keystore/that/should/not/exist")
                              .put("keystore_password", "cassandra")
                              .build());
        }).start())
        {
            // Invoke the same code vs duplicating any code from the JMXGetterCheckTest
            JMXGetterCheckTest.testAllValidGetters(cluster);
        }
    }

    @Test
    public void testClientAuth() throws Throwable
    {
        try (Cluster cluster = builder().withNodes(1).withConfig(c -> {
            c.with(Feature.JMX);
            c.set("jmx_encryption_options",
                  ImmutableMap.builder().putAll(validKeystore)
                              .put("enabled", true)
                              .put("require_client_auth", true)
                              .build());
        }).start())
        {
            Map<String, Object> jmxEnv = new HashMap<>();

            String[] enabledProtocols = new String[]{"TLSv1.2","TLSv1.1"};
            String[] cipherSuites = new String[]{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"};

            EncryptionOptions jmxClientEncryptionOptions = new EncryptionOptions()
                                                           .withKeyStore(TlsTestUtils.SERVER_KEYSTORE_PATH)
                                                           .withKeyStorePassword(TlsTestUtils.SERVER_KEYSTORE_PASSWORD)
                                                           .withTrustStore(TlsTestUtils.SERVER_TRUSTSTORE_PATH)
                                                           .withTrustStorePassword(TlsTestUtils.SERVER_TRUSTSTORE_PASSWORD)
                                                           .withCipherSuites(cipherSuites)
                                                           .withAcceptedProtocols(Arrays.asList(enabledProtocols))
                                                           .withEnabled(true);
            JMXTestSslRMIClientSocketFactory clientFactory = new JMXTestSslRMIClientSocketFactory(jmxClientEncryptionOptions);
            //jmxEnv.put(RMIConnectorServer.RMI_CLIENT_SOCKET_FACTORY_ATTRIBUTE, clientFactory);
            //jmxEnv.put("com.sun.jndi.rmi.factory.socket", clientFactory);
            // Invoke the same code vs duplicating any code from the JMXGetterCheckTest
            JMXGetterCheckTest.testAllValidGetters(cluster, jmxEnv);
        }
    }

    private static class JMXTestSslRMIClientSocketFactory implements RMIClientSocketFactory, Serializable
    {
        private final EncryptionOptions jmxEncryptionOptions;
        public JMXTestSslRMIClientSocketFactory(EncryptionOptions jmxEncryptionOptions)
        {
            this.jmxEncryptionOptions = jmxEncryptionOptions;
        }

        public Socket createSocket(String host, int port) throws IOException
        {
            // Retrieve the SSLSocketFactory
            //
            final SocketFactory sslSocketFactory = getDefaultClientSocketFactory();
            // Create the SSLSocket
            //
            final SSLSocket sslSocket = (SSLSocket)
                                        sslSocketFactory.createSocket(host, port);
            // Set the SSLSocket Enabled Cipher Suites
            //
            sslSocket.setEnabledCipherSuites(jmxEncryptionOptions.cipherSuitesArray());
            // Set the SSLSocket Enabled Protocols
            //
            sslSocket.setEnabledProtocols(jmxEncryptionOptions.acceptedProtocolsArray());
            // Return the preconfigured SSLSocket
            //
            return sslSocket;
        }

        private SocketFactory getDefaultClientSocketFactory() throws SSLException
        {
            return jmxEncryptionOptions.sslContextFactoryInstance.createJSSESslContext(EncryptionOptions.ClientAuth.NOT_REQUIRED).getSocketFactory();
        }
    }
}
