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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.constants.JwePayloadProcessingConstants;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.exceptions.JwePayloadProcessingException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.List;

/**
 * Utility class for JWK related operations.
 */
public class JwkUtils {

    private static final Log log = LogFactory.getLog(JwkUtils.class);

    /**
     * Get encryption jwk from JWKS list when JWKS Uri is given.
     *
     * @param jwksUri - JWKS Uri
     * @param encryptionAlgorithm encryption algorithm
     * @return - encryption JWK from the jwks url
     * @throws JwePayloadProcessingException thrown when error occurs while retrieving the JWK
     */
    public static JWK getEncryptionJWKFromJWKS(String jwksUri, JWEAlgorithm encryptionAlgorithm)
            throws JwePayloadProcessingException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Attempting to retrieve encryption jwk from the Jwks uri: %s , algorithm : %s",
                    jwksUri, encryptionAlgorithm));
        }
        try {
            JWKSet publicKeys = JWKSet.load(new URL(jwksUri));
            // Get the first key, use as enc and alg from the list
            JWKMatcher keyMatcherWithAlgAndEncryptionUse =
                    new JWKMatcher.Builder().algorithm(encryptionAlgorithm).keyUse(KeyUse.ENCRYPTION).build();
            List<JWK> jwkList = new JWKSelector(keyMatcherWithAlgAndEncryptionUse).select(publicKeys);

            if (jwkList.isEmpty()) {
                // If empty, then get the first key, use as enc from the list
                JWKMatcher keyMatcherWithEncryptionUse = new JWKMatcher.Builder().keyUse(KeyUse.ENCRYPTION).build();
                jwkList = new JWKSelector(keyMatcherWithEncryptionUse).select(publicKeys);

                if (jwkList.isEmpty()) {
                    // failover defaults to ->, then get the first key, use as sig from the list
                    JWKMatcher keyMatcherWithSignatureUse = new JWKMatcher.Builder().keyUse(KeyUse.SIGNATURE).build();
                    jwkList = new JWKSelector(keyMatcherWithSignatureUse).select(publicKeys);
                }
            }

            if (jwkList.isEmpty()) {
                throw new JwePayloadProcessingException(String.format("Failed to retrieve valid jwk from " +
                        "jwks uri: %s, algorithm : %s ", jwksUri, encryptionAlgorithm));
            } else {
                return jwkList.get(0);
            }
        } catch (ParseException | IOException e) {
            throw new JwePayloadProcessingException(String.format("Failed to retrieve jwk from jwks uri: %s, " +
                    "algorithm : %s", jwksUri, encryptionAlgorithm), e);
        }
    }

    /**
     * Get kid value from the jwk
     *
     * @param encryptionJwk Encryption jwk
     * @return
     */
    public static String getKidValueFromJwk(JWK encryptionJwk) {

        String kid;
        Certificate publicCert;
        if (encryptionJwk.getKeyID() != null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Kid value is available in jwk %s .", encryptionJwk.getKeyID()));
            }
            kid = encryptionJwk.getKeyID();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Kid value is not available in jwk, attempting to set x5c thumbprint as kid.");
            }
            try {
                publicCert = getPublicCertFromJWK(encryptionJwk);
                kid = getJwkThumbPrint(publicCert);
            } catch (JwePayloadProcessingException e) {
                log.error(String.format("Failed to set x5c thumbprint as kid value due to %s", e));
                kid = null;
            }
        }
        return kid;
    }

    /**
     * Get public certificate from JWK
     *
     * @param jwk   JWK
     * @return  Public certificate
     * @throws JwePayloadProcessingException  When failed to retrieve the certificate
     */
    private static X509Certificate getPublicCertFromJWK(JWK jwk) throws JwePayloadProcessingException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Attempting to retrieve public certificate from the Jwk kid: %s ."
                    , jwk.getKeyID()));
        }
        X509Certificate certificate;
        if (jwk != null && jwk.getParsedX509CertChain() != null) {
            certificate = jwk.getParsedX509CertChain().get(0);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Retrieved the public signing certificate successfully from the " +
                        "jwk : %s .", jwk));
            }
            return certificate;
        }
        throw new JwePayloadProcessingException("Failed to retrieve public certificate from jwk due to null.");
    }

    /**
     * Method to extract the SHA-1 JWK thumbprint from certificates.
     *
     * @param certificate x509 certificate
     * @return String thumbprint
     * @throws JwePayloadProcessingException When failed to extract thumbprint
     */
    public static String getJwkThumbPrint(Certificate certificate) throws JwePayloadProcessingException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Calculating SHA-1 JWK thumb-print for certificate: %s", certificate.toString()));
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance(JwePayloadProcessingConstants.X509);
            ByteArrayInputStream byteStream = new ByteArrayInputStream(certificate.getEncoded());
            X509Certificate x509 = (X509Certificate) cf.generateCertificate(byteStream);
            Base64URL jwkThumbprint = RSAKey.parse(x509).computeThumbprint(JwePayloadProcessingConstants.SHA1);
            String thumbprintString = jwkThumbprint.toString();
            if (log.isDebugEnabled()) {
                log.debug(String.format("Calculated SHA-1 JWK thumbprint %s from the certificate",
                        thumbprintString));
            }
            return thumbprintString;
        } catch (CertificateException | JOSEException e) {
            throw new JwePayloadProcessingException("Error occurred while generating SHA-1 JWK thumbprint", e);
        }
    }
}
