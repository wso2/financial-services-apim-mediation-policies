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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.SynapseException;
import org.apache.synapse.commons.json.JsonUtil;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.financial.services.apim.mediation.policies.jws.constants.JwsConstants;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Utility class for JWS (JSON Web Signature) related operations.
 */
public class JwsUtils {

    private static final Log log = LogFactory.getLog(JwsUtils.class);

    /**
     * Retrieves the value of a specific name from the additional SP properties array.
     *
     * @param additionalSpProperties JSONArray containing additional SP properties
     * @param name The name to search for in the additional SP properties
     * @return The value associated with the name, or null if the name is not found
     */
    public static String getAdditionalSpProperty(JSONArray additionalSpProperties, String name) {

        if (additionalSpProperties == null || additionalSpProperties.length() == 0) {
            return null;
        }

        for (int i = 0; i < additionalSpProperties.length(); i++) {
            JSONObject property = additionalSpProperties.getJSONObject(i);
            if (name.equals(property.get("name"))) {
                return property.getString("value");
            }
        }

        return null;
    }

    /**
     * Retrieves the additional SP properties from the application data JSON.
     * @param applicationDataJson JSONObject containing application data
     * @return JSONArray of additional SP properties, or an empty JSONArray if not found
     */
    public static JSONArray getAdditionalSpProperties(JSONObject applicationDataJson) {

        if (applicationDataJson == null || !applicationDataJson.has(JwsConstants.ADVANCED_CONFIGURATIONS)) {
            return new JSONArray();
        }

        JSONObject advancedConfigurations = applicationDataJson.optJSONObject(JwsConstants.ADVANCED_CONFIGURATIONS);
        if (advancedConfigurations == null || !advancedConfigurations.has(JwsConstants.ADDITIONAL_SP_PROPERTIES)) {
            return new JSONArray();
        }

        return advancedConfigurations.optJSONArray(JwsConstants.ADDITIONAL_SP_PROPERTIES);
    }

    /**
     * Returns a sorted set of deferred critical headers that are marked as critical in the JWS header
     * according to specifications, but are not validated by the Nimbus library during signature verification.
     *
     * These headers are acknowledged and deferred, meaning the Nimbus library will skip their validation,
     * assuming that their semantics will be enforced separately in application-specific logic.
     * It is the responsibility of the caller to validate these critical parameters after signature
     * verification. If any of these validations fail, the overall JWS verification must be considered failed.
     *
     * @return Sorted set of deferred critical headers
     */
    public static Set<String> getDifferedCritHeaders() {

        return new TreeSet<>(Arrays.asList(
                JwsConstants.IAT_CLAIM_KEY,
                JwsConstants.ISS_CLAIM_KEY,
                JwsConstants.TAN_CLAIM_KEY
        ));
    }

    /**
     * Extracts the payload from the Axis2 message context based on the content type header.
     *
     * @param axis2MessageContext Axis2 message context containing the request payload
     * @param headers Transport headers from the Axis2 message context
     * @return Payload as a string, either in XML or JSON format
     */
    public static String extractPayload(org.apache.axis2.context.MessageContext axis2MessageContext,
                                        Map<String, String> headers) {

        String payload;
        if (headers.containsKey(JwsConstants.CONTENT_TYPE_TAG)) {
            String contentType = headers.get(JwsConstants.CONTENT_TYPE_TAG);
            if (contentType.contains(JwsConstants.TEXT_XML_CONTENT_TYPE)
                    || contentType.contains(JwsConstants.APPLICATION_XML_CONTENT_TYPE)) {
                payload = axis2MessageContext.getEnvelope().getBody().getFirstElement().toString();
            } else {
                payload = JsonUtil.jsonPayloadToString(axis2MessageContext);
            }
        } else {
            payload = JsonUtil.jsonPayloadToString(axis2MessageContext);
        }

        return payload;
    }

    /**
     * Method to reconstruct a detached JWS with encoded payload.
     *
     * @param jwSignature Detached JWS
     * @param payload HTTP request payload
     * @return boolean
     */
    public static String reconstructJws(String jwSignature, String payload) throws SynapseException {

        // GET requests and DELETE requests will not need message signing.
        if (StringUtils.isEmpty(payload)) {
            throw new SynapseException("Payload is required for JWS reconstruction");
        }

        String[] jwsParts = jwSignature.split("\\.");

        if (log.isDebugEnabled()) {
            log.debug(String.format("Found %d parts in JWS for reconstruction", jwsParts.length));
        }

        // Add Base64Url encoded payload.
        if (jwsParts.length == 3) {
            jwsParts[1] = Base64URL.encode(payload).toString();

            // Reconstruct JWS with `.` deliminator
            return String.join(".", jwsParts);
        } else if (jwsParts.length == 5) {
            throw new SynapseException("Not supported for signed and encrypted JWTs.");
        }

        throw new SynapseException("Required number of parts not found in JWS for reconstruction");
    }

    /**
     * If the b64 header is not available or is true, the payload was b64 encoded before signing the signature.
     *
     * @param jwsHeader JWSHeader containing the b64 claim
     * @return Boolean
     */
    public static boolean isPayloadB64Encoded(JWSHeader jwsHeader) {

        Object b64Value = jwsHeader.getCustomParam(JwsConstants.B64_CLAIM_KEY);
        return b64Value != null ? ((Boolean) b64Value) : true;
    }

    /**
     * Creates a JWSVerifier based on the provided public key, JWS header and deferred critical headers.
     *
     * @param publicKey The public key used for signature verification
     * @param header The JWS header containing algorithm and other metadata
     * @param deferredCritHeaders Set of deferred critical headers that are not validated by the Nimbus library
     * @return JWSVerifier instance for the specified algorithm
     * @throws JOSEException
     * @throws SynapseException
     */
    public static JWSVerifier getJwsVerifier(PublicKey publicKey, JWSHeader header, Set<String> deferredCritHeaders)
            throws JOSEException, SynapseException {

        RSAPublicKey rsaKey = null;
        ECPublicKey ecKey = null;

        if (publicKey instanceof RSAPublicKey) {
            rsaKey = (RSAPublicKey) publicKey;
        } else if (publicKey instanceof ECPublicKey) {
            ecKey = (ECPublicKey) publicKey;
        }

        if (RSASSAVerifier.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {
            // Define JWSVerifier for JWS signed with RSA Signing alg.
            return new RSASSAVerifier(rsaKey, deferredCritHeaders);
        } else if (ECDSAVerifier.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {
            return new ECDSAVerifier(ecKey, deferredCritHeaders);
        } else {
            String errorMessage = "The " + header.getAlgorithm().getName() + " algorithm is not " +
                    "supported by the solution";
            log.error(errorMessage);
            throw new SynapseException(errorMessage);
        }
    }

}
