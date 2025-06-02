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

package org.wso2.financial.services.apim.mediation.policies.consent.enforcement;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.financial.services.apim.mediation.policies.consent.enforcement.constants.ConsentEnforcementConstants;
import org.wso2.financial.services.apim.mediation.policies.consent.enforcement.utils.ConsentEnforcementUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

/**
 * Mediator to enforce consent for the request.
 */
public class ConsentEnforcementMediator extends AbstractMediator {

    private static final Log log = LogFactory.getLog(ConsentEnforcementMediator.class);

    private String consentIdClaimName;
    private String identityServerBaseUrl;

    @Override
    public boolean mediate(MessageContext messageContext) {

        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        Map<String, Object> headers = (Map<String, Object>)
                axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        String extractedConsentId;
        try {
            extractedConsentId = ConsentEnforcementUtils.extractConsentIdFromJwtToken(headers, consentIdClaimName);
        } catch (UnsupportedEncodingException e) {
            // TODO: handle error properly
            return false;
        }

        if (StringUtils.isBlank(extractedConsentId)) {
            // TODO: handle error properly
            return false;
        }

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(ConsentEnforcementConstants.CONSENT_ID_TAG,
                extractedConsentId);
        additionalParams.put(ConsentEnforcementConstants.ELECTED_RESOURCE_TAG,
                messageContext.getProperty(ConsentEnforcementConstants.API_ELECTED_RESOURCE));
        additionalParams.put(ConsentEnforcementConstants.RESOURCE_PARAMS_TAG,
                ConsentEnforcementUtils.getResourceParamMap(messageContext));
         additionalParams.put(ConsentEnforcementConstants.USER_ID_TAG,
                 messageContext.getProperty(ConsentEnforcementConstants.USER_ID));
         additionalParams.put(ConsentEnforcementConstants.CLIENT_ID_TAG,
                 messageContext.getProperty(ConsentEnforcementConstants.CONSUMER_KEY));

        JSONObject validationRequest;
        try {
            validationRequest = ConsentEnforcementUtils
                    .createValidationRequestPayload(axis2MessageContext, headers, additionalParams);
        } catch (JSONException e) {
            // TODO: handle error properly
            return false;
        }

        String enforcementJWTPayload = ConsentEnforcementUtils.generateJWT(validationRequest.toString());

        JSONObject jsonResponse;
        try {
            String consentValidationEndpoint = identityServerBaseUrl +
                    ConsentEnforcementConstants.CONSENT_VALIDATE_ENDPOINT;
            String response = ConsentEnforcementUtils
                    .invokeConsentValidationService(enforcementJWTPayload, consentValidationEndpoint);
            jsonResponse = new JSONObject(response);
        } catch (IOException | APIManagementException e) {
            // TODO: handle error properly
            return false;
        }

        if (!jsonResponse.has(ConsentEnforcementConstants.IS_VALID)) {
            // TODO: handle error properly
            return false;
        }

        boolean isValid = jsonResponse.getBoolean(ConsentEnforcementConstants.IS_VALID);
        if (!isValid) {
            // TODO: handle error properly
            return false;
        }

        // Updating the request payload before sending to the backend
        if (!jsonResponse.isNull(ConsentEnforcementConstants.MODIFIED_PAYLOAD)) {
            Object modifiedPayloadObj = jsonResponse.get(ConsentEnforcementConstants.MODIFIED_PAYLOAD);
            if (modifiedPayloadObj != null) {
                JsonUtil.newJsonPayload(axis2MessageContext, modifiedPayloadObj.toString(), true, true);
            }
        }

        // Setting the consent information in the header for the backend to use
        if (!jsonResponse.isNull(ConsentEnforcementConstants.CONSENT_INFO)) {
            Object consentInformationObj = jsonResponse.get(ConsentEnforcementConstants.CONSENT_INFO);
            if (consentInformationObj != null) {
                headers.put(ConsentEnforcementConstants.INFO_HEADER_TAG, consentInformationObj.toString());
                axis2MessageContext.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headers);
            }
        }

        return true;
    }

    public String getConsentIdClaimName() {
        return consentIdClaimName;
    }

    public void setConsentIdClaimName(String consentIdClaimName) {
        this.consentIdClaimName = consentIdClaimName;
    }

    public String getIdentityServerBaseUrl() {
        return identityServerBaseUrl;
    }

    public void setIdentityServerBaseUrl(String identityServerBaseUrl) {
        this.identityServerBaseUrl = identityServerBaseUrl;
    }
}
