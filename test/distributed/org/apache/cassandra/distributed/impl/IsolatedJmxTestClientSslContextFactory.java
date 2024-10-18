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

package org.apache.cassandra.distributed.impl;

import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.lang3.StringUtils;

import org.apache.cassandra.config.EncryptionOptions;
import org.apache.cassandra.io.util.File;

/**
 * Simplied and independent version of {@link org.apache.cassandra.security.FileBasedSslContextFactory} for
 * testing TLS based JMX clients that require configuring keystore and/or truststore.
 */
public class IsolatedJmxTestClientSslContextFactory
{
    protected final Map<String, Object> parameters;
    protected String keystore;
    protected String keystore_password;
    protected final String truststore;
    protected final String truststore_password;
    protected final String protocol;
    protected final String algorithm;
    protected final String store_type;

    public IsolatedJmxTestClientSslContextFactory(Map<String, Object> parameters)
    {
        this.parameters = parameters;
        keystore = getString(EncryptionOptions.ConfigKey.KEYSTORE.getKeyName());
        keystore_password = getString(EncryptionOptions.ConfigKey.KEYSTORE_PASSWORD.getKeyName());
        truststore = getString(EncryptionOptions.ConfigKey.TRUSTSTORE.getKeyName());
        truststore_password = getString(EncryptionOptions.ConfigKey.TRUSTSTORE_PASSWORD.getKeyName());
        protocol = getString(EncryptionOptions.ConfigKey.PROTOCOL.getKeyName(), "TLS");
        algorithm = getString(EncryptionOptions.ConfigKey.ALGORITHM.getKeyName());
        store_type = getString(EncryptionOptions.ConfigKey.STORE_TYPE.getKeyName(), "JKS");
    }

    protected String getString(String key, String defaultValue)
    {
        return parameters.get(key) == null ? defaultValue : (String) parameters.get(key);
    }

    protected String getString(String key)
    {
        return (String) parameters.get(key);
    }

    @SuppressWarnings("unchecked")
    protected List<String> getStringList(String key)
    {
        return (List<String>) parameters.get(key);
    }

    protected Boolean getBoolean(String key, boolean defaultValue)
    {
        return parameters.get(key) == null ? defaultValue : (Boolean) parameters.get(key);
    }

    protected Boolean getBoolean(String key)
    {
        return (Boolean) this.parameters.get(key);
    }

    protected TrustManagerFactory buildTrustManagerFactory() throws SSLException
    {
        try (InputStream tsf = Files.newInputStream(File.getPath(truststore)))
        {
            final String algorithm = this.algorithm == null ? TrustManagerFactory.getDefaultAlgorithm() : this.algorithm;
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
            KeyStore ts = KeyStore.getInstance(store_type);

            final char[] truststorePassword = StringUtils.isEmpty(truststore_password) ? null : truststore_password.toCharArray();
            ts.load(tsf, truststorePassword);
            tmf.init(ts);
            return tmf;
        }
        catch (Exception e)
        {
            throw new SSLException("failed to build trust manager store for secure connections", e);
        }
    }

    protected KeyManagerFactory buildKeyManagerFactory() throws SSLException
    {
        final String algorithm = this.algorithm == null ? KeyManagerFactory.getDefaultAlgorithm() : this.algorithm;

        if (keystore != null)
        {
            try (InputStream ksf = Files.newInputStream(File.getPath(keystore)))
            {
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
                KeyStore ks = KeyStore.getInstance(store_type);
                final char[] password = keystore_password.toCharArray();
                ks.load(ksf, password);
                kmf.init(ks, password);
                return kmf;
            }
            catch (Exception e)
            {
                throw new SSLException("failed to build key manager store for secure connections", e);
            }
        }
        else
        {
            return null;
        }
    }

    public SSLContext createSSLContext() throws SSLException
    {
        TrustManager[] trustManagers = buildTrustManagerFactory().getTrustManagers();
        KeyManagerFactory kmf = buildKeyManagerFactory();
        try
        {
            SSLContext ctx = SSLContext.getInstance(protocol);
            ctx.init(kmf != null ? kmf.getKeyManagers() : null, trustManagers, null);
            return ctx;
        }
        catch (Exception e)
        {
            throw new SSLException("Error creating/initializing the SSL Context", e);
        }
    }
}
