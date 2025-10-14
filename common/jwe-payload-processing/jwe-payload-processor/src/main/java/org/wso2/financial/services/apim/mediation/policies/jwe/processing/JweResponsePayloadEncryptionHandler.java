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

package org.wso2.financial.services.apim.mediation.policies.jwe.processing;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.AbstractSynapseHandler;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseException;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.transport.nhttp.NhttpConstants;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.constants.JwePayloadProcessingConstants;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.exceptions.JwePayloadProcessingException;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.util.JwePayloadProcessingUtils;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.util.JwkUtils;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

/**
 * Handler class for JWE Response Payload Encryption.
 */
public class JweResponsePayloadEncryptionHandler extends AbstractSynapseHandler {

    private static final Log log = LogFactory.getLog(JweResponsePayloadEncryptionHandler.class);

    private String jweEncryptionAlg;
    private String jweEncryptionMethod;
    /**
     * Constructor for JwsResponseSignatureHandler.
     */
    public JweResponsePayloadEncryptionHandler() {

        log.debug("Initializing JweResponsePayloadEncryptionHandler to append jwe encrypted response.");
    }

    @Override
    public boolean handleRequestInFlow(MessageContext messageContext) {
        return true;
    }

    @Override
    public boolean handleRequestOutFlow(MessageContext messageContext) {
        return true;
    }

    @Override
    public boolean handleResponseInFlow(MessageContext messageContext) {
        return true;
    }

    /**
     * Method to encrypt the response payload using JWE and set the encrypted payload back to the message context.
     *This method will only proceed with the encryption if the response code is 200 or 201.
     * <p>
     * This implementation supports only "RSA-OAEP-256", "RSA-OAEP", "RSA-OAEP-384", "RSA-OAEP-512" and "RSA1_5" as
     * encryption algorithms and "A128GCM", "A256GCM" and "A192GCM" as encryption methods.
     *
     * @param messageContext  The message context
     * @return true if the mediation is successful, false otherwise
     */
    @Override
    public boolean handleResponseOutFlow(MessageContext messageContext) {

        // Set the JWE encryption algorithm and method from the message context properties.
        setProperties(messageContext);

        // Build the payload from messageContext.
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Map<String, Object> headers = (Map<String, Object>) axis2MC
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        String contentType = JwePayloadProcessingUtils.getContentType(headers);

        // Skip encryption if the response is an error scenario
        Object statusCodeProperty = ((Axis2MessageContext) messageContext).getAxis2MessageContext()
                .getProperty(NhttpConstants.HTTP_SC);
        int httpStatusCode = statusCodeProperty instanceof Integer ?  (int) statusCodeProperty :
                Integer.parseInt(statusCodeProperty.toString());
        if (httpStatusCode > 201) {
            if (log.isDebugEnabled()) {
                log.debug("Response encryption is skipped as the response code is: " + httpStatusCode);
            }
            return true;
        }

        Optional<String> payloadString;
        try {
            payloadString = JwePayloadProcessingUtils.buildMessagePayloadFromMessageContext(axis2MC, contentType);
            if (payloadString.isPresent()) {
                if (log.isDebugEnabled()) {
                    log.debug("Encrypting the response payload");
                }

                JWEAlgorithm jweAlg = JWEAlgorithm.parse(getJweEncryptionAlg());
                EncryptionMethod encMethod = EncryptionMethod.parse(getJweEncryptionMethod());

                JSONObject applicationDataJson = new JSONObject((String) messageContext
                        .getProperty(JwePayloadProcessingConstants.APPLICATION_DATA_PROPERTY));

                JSONArray additionalSpProperties = JwePayloadProcessingUtils
                        .getAdditionalSpProperties(applicationDataJson);
                String jwksUrl = JwePayloadProcessingUtils.getAdditionalSpProperty(additionalSpProperties,
                        JwePayloadProcessingConstants.JWS_SP_PROPERTY_KEY);

                JWK encryptionJwk = JwkUtils.getEncryptionJWKFromJWKS(jwksUrl, jweAlg);
                RSAPublicKey publicKey = RSAKey.parse(encryptionJwk.toJSONString()).toRSAPublicKey();
                String kid = JwkUtils.getKidValueFromJwk(encryptionJwk);

                // Encrypt the payload
                JWEHeader header = new JWEHeader.Builder(jweAlg, encMethod).keyID(kid).build();
                Payload payloadData = new Payload(payloadString.get());
                JWEObject jweObject = new JWEObject(header, payloadData);
                JWEEncrypter encrypter = new RSAEncrypter(publicKey);
                jweObject.encrypt(encrypter);
                String jweTokenString = jweObject.serialize();
                log.debug("Encrypted JWE Token: " + jweTokenString);

                // Set the encrypted payload back to the message context.
                JwePayloadProcessingUtils.addEncryptedPayloadToMessageContext(jweTokenString, messageContext);
                return true;
            } else {
                log.debug("Payload cannot be encrypted as the payload is not present.");
                return true;
            }
        } catch (JwePayloadProcessingException e) {
            log.error("Error occurred while extracting the payload from message context", e);
            throw new SynapseException("Error occurred while extracting the payload from message context", e);
        } catch (JOSEException e) {
            log.error("Error occurred while generating the encrypted payload", e);
            throw new SynapseException("Error occurred while generating the encrypted payload", e);
        } catch (ParseException e) {
            log.error("Error occurred while parsing the encrypted payload", e);
            throw new SynapseException("Error occurred while parsing the encrypted payload", e);
        }
    }

    /**
     * Set the JWE encryption algorithm and method from the message context properties.
     *
     * @param messageContext The message context
     */
    private void setProperties(MessageContext messageContext) {

        setJweEncryptionAlg((String) messageContext.getProperty(JwePayloadProcessingConstants.JWE_ENCRYPTION_ALG));
        setJweEncryptionMethod((String) messageContext
                .getProperty(JwePayloadProcessingConstants.JWE_ENCRYPTION_METHOD));
    }

    public String getJweEncryptionAlg() {
        return jweEncryptionAlg;
    }

    public void setJweEncryptionAlg(String jweEncryptionAlg) {
        this.jweEncryptionAlg = jweEncryptionAlg;
    }

    public String getJweEncryptionMethod() {
        return jweEncryptionMethod;
    }

    public void setJweEncryptionMethod(String jweEncryptionMethod) {
        this.jweEncryptionMethod = jweEncryptionMethod;
    }
}
