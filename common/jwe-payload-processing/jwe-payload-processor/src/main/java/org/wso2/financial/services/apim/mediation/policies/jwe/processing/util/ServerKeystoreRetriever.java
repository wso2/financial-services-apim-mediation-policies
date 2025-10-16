/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 * <p>
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 *     http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.financial.services.apim.mediation.policies.jwe.processing.util;

import org.apache.commons.lang3.StringUtils;
import org.apache.synapse.SynapseException;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.constants.JwePayloadProcessingConstants;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * Utility to retrieve Server certificates.
 */
public class ServerKeystoreRetriever {

    private KeyStore keyStore = null;
    private static final Object lock = new Object();
    static ServerKeystoreRetriever retriever;

    // Internal KeyStore Password.
    private final char[] keyStorePassword;


    /**
     * Private Constructor of config parser.
     */
    private ServerKeystoreRetriever() {

        String keyStoreLocation = ServerConfiguration.getInstance()
                .getFirstProperty(JwePayloadProcessingConstants.KEYSTORE_LOCATION_CONF_KEY);
        String keyStorePasswordConfig = ServerConfiguration.getInstance()
                .getFirstProperty(JwePayloadProcessingConstants.KEYSTORE_PASS_CONF_KEY);
        keyStore = loadKeyStore(keyStoreLocation, keyStorePasswordConfig);
        keyStorePassword = keyStorePasswordConfig.toCharArray();
    }

    /**
     * Singleton getInstance method to create only one object.
     *
     * @return FinancialServicesConfigParser object
     */
    public static ServerKeystoreRetriever getInstance() {

        synchronized (lock) {
            if (retriever == null) {
                retriever = new ServerKeystoreRetriever();
            }
        }
        return retriever;
    }

    /**
     * Load the keystore when the location and password is provided.
     *
     * @param keyStoreLocation Location of the keystore
     * @param keyStorePassword Keystore password
     * @return Keystore as an object
     */
    public static KeyStore loadKeyStore(String keyStoreLocation, String keyStorePassword) {

        KeyStore keyStore;

        try (FileInputStream inputStream = new FileInputStream(keyStoreLocation)) {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(inputStream, keyStorePassword.toCharArray());
            return keyStore;
        } catch (KeyStoreException e) {
            throw new SynapseException("Error while retrieving aliases from keystore: " + keyStoreLocation, e);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new SynapseException("Error while loading keystore", e);
        }
    }

    /**
     * Returns the signing key based on the alias provided.
     *
     * @param alias Alias of the signing key to retrieve
     * @return Optional<Key> The signing key as an Optional
     */
    public Key getSigningKey(String alias) {

        if (StringUtils.isNotBlank(alias)) {
            try {
                return keyStore.getKey(alias, keyStorePassword);
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                throw new SynapseException("Unable to retrieve certificate", e);
            }
        }

        return null;
    }
}
