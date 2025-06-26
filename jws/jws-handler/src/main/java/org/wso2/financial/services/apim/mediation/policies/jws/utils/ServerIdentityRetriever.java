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

package org.wso2.financial.services.apim.mediation.policies.jws.utils;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.SynapseException;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.financial.services.apim.mediation.policies.jws.constants.JwsHandlerConstants;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Optional;

/**
 * Utility to retrieve Server certificates.
 */
public class ServerIdentityRetriever {

    private static KeyStore keyStore = null;

    // Internal KeyStore Password.
    private static char[] keyStorePassword;

    private static final Log log = LogFactory.getLog(ServerIdentityRetriever.class);

    static {
        // Static Initialize Internal Keystore.
        String keyStoreLocation = ServerConfiguration.getInstance()
                .getFirstProperty(JwsHandlerConstants.KEYSTORE_LOCATION_CONF_KEY);
        String keyStorePassword = ServerConfiguration.getInstance()
                .getFirstProperty(JwsHandlerConstants.KEYSTORE_PASS_CONF_KEY);

        try {
            ServerIdentityRetriever.keyStore = loadKeyStore(keyStoreLocation, keyStorePassword);
            ServerIdentityRetriever.keyStorePassword = keyStorePassword.toCharArray();
        } catch (SynapseException e) {
            log.error("Unable to load InternalKeyStore", e);
        }
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
            throw new SynapseException("Error while retrieving aliases from keystore", e);
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
    public static Optional<Key> getSigningKey(String alias) {

        if (StringUtils.isNotBlank(alias)) {
            try {
                // The requested key, or
                // null if the given alias does not exist or does not identify a key-related entry.
                return Optional.of(keyStore.getKey(alias, keyStorePassword));
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                throw new SynapseException("Unable to retrieve certificate", e);
            }
        }

        return Optional.empty();
    }

    public static Certificate getCertificate(String alias) throws KeyStoreException {

        return keyStore.getCertificate(alias);
    }
}
