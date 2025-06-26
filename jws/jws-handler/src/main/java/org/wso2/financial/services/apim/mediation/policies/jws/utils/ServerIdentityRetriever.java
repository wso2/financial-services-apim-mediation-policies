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
import java.util.HashMap;
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
     * Returns the signing key using the signing Certificate.
     * @param certificateType Signing certificate
     * @param environmentType Sandbox or Production environment
     * @return Key The signing key
     */
    public static Optional<Key> getPrimaryCertificate(JwsHandlerConstants.CertificateType certificateType,
                                                      JwsHandlerConstants.EnvironmentType environmentType,
                                                      HashMap<JwsHandlerConstants.EnvironmentType, String>
                                                              signingCertAliasMap) {
        String certAlias;

        if (certificateType.equals(JwsHandlerConstants.CertificateType.SIGNING)) {

            certAlias = getCertAlias(certificateType, environmentType, signingCertAliasMap);

            if (StringUtils.isNotBlank(certAlias)) {
                try {
                    // The requested key, or
                    // null if the given alias does not exist or does not identify a key-related entry.
                    return Optional.of(keyStore.getKey(certAlias, keyStorePassword));
                } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                    throw new SynapseException("Unable to retrieve certificate", e);
                }
            }

        }
        return Optional.empty();
    }

    /**
     * Returns signing key used at production environment.
     * @param certificateType signing certificate
     * @return Key signing key
     */
    public static Optional<Key> getPrimaryCertificate(JwsHandlerConstants.CertificateType certificateType,
                                                      HashMap<JwsHandlerConstants.EnvironmentType, String>
                                                              signingCertAliasMap) {

        return getPrimaryCertificate(certificateType, JwsHandlerConstants.EnvironmentType.PRODUCTION,
                signingCertAliasMap);
    }

    public static Certificate getCertificate(String alias) throws KeyStoreException {

        return keyStore.getCertificate(alias);
    }

    /**
     * Returns Signing certificate alias.
     * @param certificateType signing
     * @param environmentType Production or Sandbox
     * @param signingCertAliasMap Map containing environment type and signing certificate alias
     * @return Signing certificate alias
     */
    public static String getCertAlias(JwsHandlerConstants.CertificateType certificateType,
                                      JwsHandlerConstants.EnvironmentType environmentType,
                                      HashMap<JwsHandlerConstants.EnvironmentType, String> signingCertAliasMap) {
        String certAlias = null;

        if (certificateType.equals(JwsHandlerConstants.CertificateType.SIGNING)) {
            if (keyStore == null) {
                throw new SynapseException("Internal Key Store not initialized");
            }

            if (environmentType == JwsHandlerConstants.EnvironmentType.SANDBOX) {
                certAlias = signingCertAliasMap.get(JwsHandlerConstants.EnvironmentType.SANDBOX);
            } else {
                certAlias = signingCertAliasMap.get(JwsHandlerConstants.EnvironmentType.PRODUCTION);
            }
        }
        return certAlias;
    }
}
