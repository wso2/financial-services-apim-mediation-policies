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

package org.wso2.financial.services.apim.mediation.policies.consent.enforcement.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.APIManagerConfigurationService;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.financial.services.apim.mediation.policies.consent.enforcement.constants.ConsentEnforcementConstants;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for the Consent Enforcement Policy.
 */
public class ConsentEnforcementUtils {

    private static final Log log = LogFactory.getLog(ConsentEnforcementUtils.class);
    private static final ServerConfiguration serverConfigs = ServerConfiguration.getInstance();
    private static final APIManagerConfigurationService configService = ServiceReferenceHolder.getInstance()
            .getAPIManagerConfigurationService();

    private static volatile String consentValidationEndpoint;
    private static volatile Key key;
    private static String keyStoreLocation;
    private static char[] keyStorePassword;
    private static String keyAlias;
    private static String keyPassword;

    /**
     * Method to construct resource parameter map to invoke the validation service.
     *
     * @param messageContext request context object
     * @return A Map containing resource path(ex: /aisp/accounts/{AccountId}?queryParam=urlEncodedQueryParamValue),
     * http method and context(ex: /open-banking/v3.1/aisp)
     */
    public static Map<String, String> getResourceParamMap(MessageContext messageContext) {

        Map<String, String> resourceMap = new HashMap<>();
        resourceMap.put(ConsentEnforcementConstants.RESOURCE_TAG, (String)
                messageContext.getProperty(ConsentEnforcementConstants.REST_FULL_REQUEST_PATH));
        resourceMap.put(ConsentEnforcementConstants.HTTP_METHOD_TAG, (String)
                messageContext.getProperty(ConsentEnforcementConstants.REST_METHOD));
        resourceMap.put(ConsentEnforcementConstants.CONTEXT_TAG, (String)
                messageContext.getProperty(ConsentEnforcementConstants.REST_API_CONTEXT));
        return resourceMap;
    }

    /**
     * Method to extract the consent ID from the JWT token present in the request headers.
     *
     * @param headers Transport headers from the Axis2 message context
     * @param consentIdClaimName Name of the claim that contains the consent ID
     * @return Consent ID if present in the JWT token, null otherwise
     * @throws UnsupportedEncodingException When encoding is not UTF-8
     */
    public static String extractConsentIdFromJwtToken(Map<String, Object> headers, String consentIdClaimName)
            throws UnsupportedEncodingException {

        String authHeader = (String) headers.get(ConsentEnforcementConstants.AUTH_HEADER);
        if (authHeader != null && !authHeader.isEmpty() &&
                isValidJWTToken(authHeader.replace(ConsentEnforcementConstants.BEARER_TAG, ""))) {
            String consentIdClaim = null;
            if (!authHeader.contains(ConsentEnforcementConstants.BASIC_TAG)) {
                authHeader = authHeader.replace(ConsentEnforcementConstants.BEARER_TAG, "");
                JSONObject jwtClaims = decodeBase64(authHeader.split("\\.")[1]);

                if (!jwtClaims.isNull(consentIdClaimName) && !jwtClaims.getString(consentIdClaimName).isEmpty()) {
                    consentIdClaim = jwtClaims.getString(consentIdClaimName);
                }
            }
            return consentIdClaim;
        }
        return null;
    }

    /**
     * Method to create the validation request payload.
     *
     * @param axis2MessageContext Axis2 message context
     * @param requestHeaders Transport headers from the Axis2 message context
     * @param additionalParams Additional parameters to be included in the request payload
     * @return JSONObject representing the validation request payload
     */
    public static JSONObject createValidationRequestPayload(org.apache.axis2.context.MessageContext axis2MessageContext,
                                                            Map<String, Object> requestHeaders,
                                                            Map<String, Object> additionalParams) throws JSONException {

        JSONObject validationRequest = new JSONObject();
        JSONObject headers = new JSONObject();

        requestHeaders.forEach(headers::put);
        validationRequest.put(ConsentEnforcementConstants.HEADERS_TAG, headers);

        JSONObject requestPayload = new JSONObject(JsonUtil.jsonPayloadToString(axis2MessageContext));
        validationRequest.put(ConsentEnforcementConstants.BODY_TAG, requestPayload);

        additionalParams.forEach(validationRequest::put);
        return validationRequest;
    }

    /**
     * Method to generate JWT.
     * @param payload Payload to be signed
     * @return Signed JWT
     */
    public static String generateJWT(String payload) {

        return Jwts.builder()
                .setPayload(payload)
                .signWith(SignatureAlgorithm.RS512, getSigningKey())
                .compact();
    }

    /**
     * Method to invoke consent validation service when the JWT payload is provided.
     *
     * @param enforcementJWTPayload JWT Payload
     * @return Response as a String
     * @throws IOException When failed to invoke the validation endpoint or failed to parse the response.
     */
    public static String invokeConsentValidationService(String enforcementJWTPayload, String consentValidationEndpoint)
            throws IOException, APIManagementException {

        HttpPost httpPost = new HttpPost(consentValidationEndpoint);
        StringEntity params;
        params = new StringEntity(enforcementJWTPayload);
        httpPost.setEntity(params);
        httpPost.setHeader(ConsentEnforcementConstants.CONTENT_TYPE_TAG, ConsentEnforcementConstants.JWT_CONTENT_TYPE);

        String userName = configService.getAPIManagerConfiguration()
                .getFirstProperty(ConsentEnforcementConstants.API_KEY_VALIDATOR_USERNAME);
        String password = configService.getAPIManagerConfiguration()
                .getFirstProperty(ConsentEnforcementConstants.API_KEY_VALIDATOR_PASSWORD);

        httpPost.setHeader(ConsentEnforcementConstants.AUTH_HEADER, getBasicAuthHeader(userName, password));

        HttpResponse response = HttpsClientHolder.getHttpsClient().execute(httpPost);
        InputStream in = response.getEntity().getContent();
        return IOUtils.toString(in, String.valueOf(StandardCharsets.UTF_8));
    }

    /**
     * Method to check whether the given string is a valid JWT token.
     *
     * @param jwtString JWT token string
     * @return true if the given string is a valid JWT token, false otherwise
     */
    private static boolean isValidJWTToken(String jwtString) {

        String[] jwtPart = jwtString.split("\\.");
        if (jwtPart.length != 3) {
            return false;
        }
        try {
            decodeBase64(jwtPart[0]);
            decodeBase64(jwtPart[1]);
        } catch (UnsupportedEncodingException | JSONException | IllegalArgumentException e) {
            log.error("Failed to decode the JWT token. %s", e);
            return false;
        }
        return true;
    }

    /**
     * Method to decode the base64 encoded JSON payload.
     *
     * @param payload base64 encoded payload
     * @return Decoded JSON Object
     * @throws UnsupportedEncodingException When encoding is not UTF-8
     */
    private static JSONObject decodeBase64(String payload) throws UnsupportedEncodingException {

        return new JSONObject(new String(java.util.Base64.getDecoder().decode(payload),
                String.valueOf(StandardCharsets.UTF_8)));
    }

    /**
     * Method to obtain signing key.
     *
     * @return Key as an Object.
     */
    private static Key getSigningKey() {

        if (key == null) {
            synchronized (ConsentEnforcementUtils.class) {
                if (key == null) {
                    try (FileInputStream is = new FileInputStream(getKeyStoreLocation())) {
                        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                        keystore.load(is, getKeyStorePassword());
                        key = keystore.getKey(getKeyAlias(), getKeyPassword().toCharArray());
                    } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException
                             | UnrecoverableKeyException e) {
                        log.error("Error occurred while retrieving private key from keystore ", e);
                    }
                }
            }
        }
        return key;
    }

    /**
     * Method to obtain basic auth header.
     *
     * @param username Username of Auth header
     * @param password Password of Auth header
     * @return basic auth header
     */
    private static String getBasicAuthHeader(String username, String password) {

        byte[] authHeader = Base64.getEncoder().encode((username + ConsentEnforcementConstants.COLON + password)
                .getBytes(StandardCharsets.UTF_8));
        return ConsentEnforcementConstants.BASIC_TAG + new String(authHeader, StandardCharsets.UTF_8);
    }

    private static String getKeyStoreLocation() {

        return keyStoreLocation == null ? serverConfigs
                .getFirstProperty(ConsentEnforcementConstants.KEYSTORE_LOCATION_TAG) : keyStoreLocation;
    }

    private static char[] getKeyStorePassword() {

        if (keyStorePassword == null) {
            keyStorePassword = serverConfigs
                    .getFirstProperty(ConsentEnforcementConstants.KEYSTORE_PASSWORD_TAG).toCharArray();
        }
        return Arrays.copyOf(keyStorePassword, keyStorePassword.length);
    }

    private static String getKeyAlias() {

        return keyAlias == null ? serverConfigs
                .getFirstProperty(ConsentEnforcementConstants.SIGNING_ALIAS_TAG) : keyAlias;
    }

    private static String getKeyPassword() {

        return keyPassword == null ? serverConfigs
                .getFirstProperty(ConsentEnforcementConstants.SIGNING_KEY_PASSWORD) : keyPassword;
    }
}
