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

package org.wso2.financial.services.apim.mediation.policies.jws;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.AbstractSynapseHandler;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseException;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.RESTConstants;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.financial.services.apim.mediation.policies.jws.constants.JwsHandlerConstants;
import org.wso2.financial.services.apim.mediation.policies.jws.utils.JwsHandlerUtils;
import org.wso2.financial.services.apim.mediation.policies.jws.utils.ServerIdentityRetriever;

import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Handler class for Signing Responses.
 */
public class JwsResponseHeaderHandler extends AbstractSynapseHandler {

    private static final Log log = LogFactory.getLog(JwsResponseHeaderHandler.class);

    private String xWso2ApiType;

    // TODO: get from config a strings like below
    private String productionSigningCertAlias = "wso2carbon" /*null*/;
    private String sandboxSigningCertAlias = "wso2carbon" /*null*/;
    private String signatureHeaderName = "x-jws-signature" /*null*/;
    private String signingKeyId = "1234" /*null*/;
    private String signingAlgorithm = "PS256" /*null*/;

    /**
     * Constructor for JwsResponseSignatureHandler.
     */
    public JwsResponseHeaderHandler() {

        log.debug("Initializing JwsResponseSignatureHandler to append jws response signature.");
    }

    /**
     * Handle request message coming into the engine.
     *
     * @param messageContext incoming request message context
     * @return whether mediation flow should continue
     */
    @Override
    public boolean handleRequestInFlow(MessageContext messageContext) {

        return true;

    }

    /**
     * Handle request message going out from the engine.
     *
     * @param messageContext outgoing request message context
     * @return whether mediation flow should continue
     */
    @Override
    public boolean handleRequestOutFlow(MessageContext messageContext) {

        return true;
    }

    /**
     * Handle response message coming into the engine.
     *
     * @param messageContext incoming response message context
     * @return whether mediation flow should continue
     */
    @Override
    public boolean handleResponseInFlow(MessageContext messageContext) {

        return appendJwsSignatureToResponse(messageContext);
    }

    /**
     * Handle response message going out from the engine.
     *
     * @param messageContext outgoing response message context
     * @return whether mediation flow should continue
     */
    @Override
    public boolean handleResponseOutFlow(MessageContext messageContext) {

        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Map headers = (Map) axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (messageContext.getEnvelope() != null && messageContext.getEnvelope().getBody() != null &&
                StringUtils.contains(messageContext.getEnvelope().getBody().toString(),
                        "Schema validation failed")) {
            // Add jws header for schema errors, This is due to schema validation happens after responseInFlow.
            // So we need to regenerate the jws for schema validation error responses.
            return appendJwsSignatureToResponse(messageContext);
        } else if (headers.containsKey(signatureHeaderName) && headers.get(signatureHeaderName) != null) {
            return true;
        } else {
            // Add jws header, if it's not added yet.
            return appendJwsSignatureToResponse(messageContext);
        }
    }

    /**
     * Method to append Jws Signature to the response.
     *
     * @param messageContext response/request message context.
     * @return jws signature response is successfully appended.
     */
    private boolean appendJwsSignatureToResponse(MessageContext messageContext) {

        setXWso2ApiType((String) messageContext.getProperty(RESTConstants.REST_API_CONTEXT));

        try {
            boolean applicable = isApplicable(messageContext);
            if (!applicable) {
                log.debug("Signature generation is not applicable for this response");
                return true;
            } else {
                log.debug("Generating signature for the response");
            }
        } catch (RuntimeException e) {
            log.debug("Internal Server Error, Unable to append jws signature", e);
            JwsHandlerUtils.returnSynapseHandlerJSONError(messageContext, JwsHandlerConstants.SERVER_ERROR_CODE,
                    getFormattedSignatureHandlingErrorResponse(messageContext, JwsHandlerConstants.SERVER_ERROR_CODE,
                            JwsHandlerConstants.INTERNAL_SERVER_ERROR,
                            "Internal Server Error, Unable to append jws signature"));
        }

        // Build the payload from messageContext.
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Map headers = (Map) axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        Optional<String> payloadString;
        try {
            payloadString = JwsHandlerUtils.buildMessagePayloadFromMessageContext(axis2MC, headers);
        } catch (SynapseException e) {
            log.error("Unable to build response payload", e);
            JwsHandlerUtils.returnSynapseHandlerJSONError(messageContext, JwsHandlerConstants.SERVER_ERROR_CODE,
                    getFormattedSignatureHandlingErrorResponse(messageContext, JwsHandlerConstants.SERVER_ERROR_CODE,
                            JwsHandlerConstants.INTERNAL_SERVER_ERROR,
                            "Internal Server Error, Unable to build response payload"));
            return true;
        }

        if (payloadString.isPresent()) {
            try {
                headers.put(signatureHeaderName, generateJWSSignature(payloadString));
            } catch (JOSEException | SynapseException e) {
                log.error("Unable to sign response", e);
                JwsHandlerUtils.returnSynapseHandlerJSONError(messageContext, JwsHandlerConstants.SERVER_ERROR_CODE,
                        getFormattedSignatureHandlingErrorResponse(messageContext,
                                JwsHandlerConstants.SERVER_ERROR_CODE, JwsHandlerConstants.INTERNAL_SERVER_ERROR,
                                "Internal Server Error, Unable to sign the response"));
                return true;
            }
        } else {
            log.debug("Signature cannot be generated as the payload is invalid or not present.");
        }
        axis2MC.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headers);
        return true;
    }

    /**
     * Provide the child classes to decide whether the signature generation is required for requestPath.
     *
     * @param messageContext OB response Object
     * @return boolean returns if request needs to be signed
     */
    public boolean isApplicable(MessageContext messageContext) {

        //Set content type for file upload get and payment file get
        if (isFilePaymentRetrieval(messageContext)) {
            setContentTypeForFileRetrieval(messageContext);
        }
        // Get response signature required API resource list.
        // TODO: get from config a string list like this (/open-banking/v3.1/pisp, /a/b/c)
        List<String> requiredAPIs = new ArrayList<>(Arrays.asList("/open-banking/v3.1/pisp", "abc"));

        if (!requiredAPIs.isEmpty() && requiredAPIs.stream()
                .noneMatch(url -> org.apache.commons.lang.StringUtils.containsIgnoreCase(getXWso2ApiType(), url))) {
            return false;
        }
        return true;
    }

    /**
     * Check whether the request is file upload retrieval or payment file retrieval.
     *
     * @param messageContext messageContext
     * @return is file payment request.
     */
    private boolean isFilePaymentRetrieval(MessageContext messageContext) {

        if (JwsHandlerConstants.GET_HTTP_METHOD.equals(messageContext.getProperty(JwsHandlerConstants.HTTP_METHOD))) {
            return JwsHandlerConstants.FILE_PAYMENT_CONSENTS_FILE.equals(
                    messageContext.getProperty(JwsHandlerConstants.API_ELECTED_RESOURCE)) ||
                    JwsHandlerConstants.FILE_PAYMENT_REPORT_FILE.equals(
                            messageContext.getProperty(JwsHandlerConstants.API_ELECTED_RESOURCE));
        }
        return false;
    }

    /**
     * Set content type for file upload retrieval or payment file retrieval when accept header is not specified.
     *
     * @param messageContext messageContext
     */
    private void setContentTypeForFileRetrieval(MessageContext messageContext) {

        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Map responseHeaders = (Map) axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (responseHeaders != null && responseHeaders.containsKey(JwsHandlerConstants.CONTENT_TYPE_TAG)) {
            if (responseHeaders.get(JwsHandlerConstants.CONTENT_TYPE_TAG).toString().contains(
                    JwsHandlerConstants.APPLICATION_OCTET_STREAM_TYPE)) {
                responseHeaders.put(JwsHandlerConstants.CONTENT_TYPE_TAG, JwsHandlerConstants.TEXT_XML_CONTENT_TYPE);
                messageContext.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, responseHeaders);
            }
        }
    }

    /**
     * Method to Generate JWS signature.
     *
     * @param payloadString payload.
     * @return String jws signature.
     */
    public String generateJWSSignature(Optional<String> payloadString) throws JOSEException {

        String jwsSignatureHeader = null;
        if (payloadString.isPresent() && StringUtils.isNotBlank(payloadString.get())) {
            HashMap<String, Object> criticalParameters = getCriticalHeaderParameters();
            HashMap<JwsHandlerConstants.EnvironmentType, String> signingCertAliasMap = getSigningCertAliasMap();

            JWSAlgorithm signingAlgorithmObject = JWSAlgorithm.parse(signingAlgorithm);
            jwsSignatureHeader = JwsHandlerUtils
                    .constructJWSSignature(payloadString.get(), criticalParameters, signingCertAliasMap,
                            signingKeyId, signingAlgorithmObject);
        } else {
            log.debug("Signature cannot be generated as the payload is invalid.");
        }
        return jwsSignatureHeader;
    }

    /**
     * HashMap to be returned with crit header keys and values.
     * can be extended at toolkit level.
     *
     * @return HashMap crit header parameters
     */
    public HashMap<String, Object> getCriticalHeaderParameters() {

        HashMap<String, Object> criticalParameters = new HashMap<>();

        // http://openbanking.org.uk/iat claim
        ZonedDateTime currentTime = ZonedDateTime.now(JwsHandlerConstants.ZONE_ID);
        criticalParameters.put(JwsHandlerConstants.IAT_CLAIM_KEY,
                currentTime.toInstant().getEpochSecond());

        // http://openbanking.org.uk/iss claim
        // TODO: get from config a string like this (0015800001HQQrZAAX)
        String signingOrgID = "0015800001HQQrZAAX";

        if (org.apache.commons.lang.StringUtils.isNotEmpty(signingOrgID)) {
            // When issued by an ASPSP iss claim is of the form {{org-id}}
            criticalParameters.put(JwsHandlerConstants.ISS_CLAIM_KEY, signingOrgID);
        } else {
            try {
                // Get signing certificate from keystore
                X509Certificate signingCert;
                signingCert = (X509Certificate) ServerIdentityRetriever.getCertificate(productionSigningCertAlias);
                criticalParameters.put(JwsHandlerConstants.ISS_CLAIM_KEY, signingCert.getSubjectDN().getName());
            } catch (KeyStoreException e) {
                log.error("Error occurred while retrieving signing certificate from keystore.", e);
            }
        }

        // http://openbanking.org.uk/tan claim
        // TODO: get from config a string like this (openbanking.org.uk)
        criticalParameters.put(JwsHandlerConstants.TAN_CLAIM_KEY, "openbanking.org.uk");

        return criticalParameters;
    }

    /**
     * Method to get the formatted error response for jws signature response.
     *
     * @param messageContext messageContext
     * @param code           error code
     * @param title          error title
     * @param errorMessage   error message
     * @return String error response
     */
    public String getFormattedSignatureHandlingErrorResponse(MessageContext messageContext, String code, String title,
                                                             String errorMessage) {

        if (!isAPIV4Request(messageContext)) {
            // API v3
            JSONObject payload = new JSONObject();
            JSONArray errorList = new JSONArray();
            JSONObject errorObj = new JSONObject();
            errorObj.put(JwsHandlerConstants.ERROR_CODE, JwsHandlerConstants.SIGNATURE_UNEXPECTED);
            errorObj.put(JwsHandlerConstants.PATH, "Header.Signature");
            errorObj.put(JwsHandlerConstants.MESSAGE, errorMessage);
            errorList.put(errorObj);
            String errorId = UUID.randomUUID().toString();
            payload.put(JwsHandlerConstants.CODE, "500 Internal Server Error");
            payload.put(JwsHandlerConstants.ID, errorId);
            payload.put(JwsHandlerConstants.MESSAGE, errorMessage);
            payload.put(JwsHandlerConstants.ERRORS, errorList);
            return payload.toString();
        } else {
            // API v4
            JSONObject payload = new JSONObject();
            JSONArray errorList = new JSONArray();
            JSONObject errorObj = new JSONObject();
            errorObj.put(JwsHandlerConstants.ERROR_CODE, JwsHandlerConstants.U020);
            errorObj.put(JwsHandlerConstants.PATH, "Header.Signature");
            errorObj.put(JwsHandlerConstants.MESSAGE, errorMessage);
            errorList.put(errorObj);
            String errorId = UUID.randomUUID().toString();
            payload.put(JwsHandlerConstants.ID, errorId);
            payload.put(JwsHandlerConstants.ERRORS, errorList);
            return payload.toString();
        }
    }

    /**
     * Method to check whether the request is API v4.
     *
     * @return boolean
     */
    private boolean isAPIV4Request(MessageContext messageContext) {

        String xWso2ApiVersion = (String) messageContext.getProperty(RESTConstants.SYNAPSE_REST_API_VERSION);
        if (xWso2ApiVersion != null) {
            return StringUtils.equalsIgnoreCase(xWso2ApiVersion, JwsHandlerConstants.VERSION_PREFIX +
                    JwsHandlerConstants.UK_API_V4_PATH);
        } else {
            return false;
        }
    }

    public HashMap<JwsHandlerConstants.EnvironmentType, String> getSigningCertAliasMap() {

        HashMap<JwsHandlerConstants.EnvironmentType, String> signingCertAliasMap = new HashMap<>();
        signingCertAliasMap.put(JwsHandlerConstants.EnvironmentType.PRODUCTION, productionSigningCertAlias);
        signingCertAliasMap.put(JwsHandlerConstants.EnvironmentType.SANDBOX, sandboxSigningCertAlias);

        return signingCertAliasMap;
    }

    public String getXWso2ApiType() {

        return xWso2ApiType;
    }

    public void setXWso2ApiType(String xWso2ApiType) {

        this.xWso2ApiType = xWso2ApiType;
    }

    public String getProductionSigningCertAlias() {

        return productionSigningCertAlias;
    }

    public void setProductionSigningCertAlias(String productionSigningCertAlias) {

        this.productionSigningCertAlias = productionSigningCertAlias;
    }

    public String getSandboxSigningCertAlias() {

        return sandboxSigningCertAlias;
    }

    public void setSandboxSigningCertAlias(String sandboxSigningCertAlias) {

        this.sandboxSigningCertAlias = sandboxSigningCertAlias;
    }

    public String getSignatureHeaderName() {

        return signatureHeaderName;
    }

    public void setSignatureHeaderName(String signatureHeaderName) {

        this.signatureHeaderName = signatureHeaderName;
    }

    public String getSigningKeyId() {

        return signingKeyId;
    }

    public void setSigningKeyId(String signingKeyId) {

        this.signingKeyId = signingKeyId;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public void setSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }
}
