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

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.protocol.HTTP;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseException;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.constants.JwePayloadProcessingConstants;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.exceptions.JwePayloadProcessingException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.ws.rs.core.MediaType;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import static org.apache.axis2.transport.base.BaseConstants.AXIOMPAYLOADNS;

/**
 * Class provides the utility methods for JWE Payload Processing.
 */
public class JwePayloadProcessingUtils {

    private static final Log log = LogFactory.getLog(JwePayloadProcessingUtils.class);

    static List<String> supportedContentTypesList = new ArrayList<String>() {{
        add(JwePayloadProcessingConstants.JWE_CONTENT_TYPE);
    }};

    /**
     * Checks if the content type is supported for payload encryption and decryption.
     * To this date, the supported content types are "application/jose+jwe" only.
     *
     * @param contentType Content-Type of the payload
     * @return true if the content type is supported by the handler
     */
    public static boolean isSupportedContentType(String contentType) {

        if (StringUtils.isEmpty(contentType)) {
            return false;
        }

        for (String type: supportedContentTypesList) {
            if (contentType.contains(type)) {
                return true;
            }
        }
        return false;
    }

    public static String getSupportedContentTypes() {
        return supportedContentTypesList.toString();
    }

    /**
     * Gets the value of the Content-Type header of the payload from the transport headers.
     *
     * @param transportHeaders transport headers of the request
     * @return the value of the Content-Type header. Empty string if the Content-Type header is missing
     * in transport headers
     */
    public static String getContentType(Map<String, Object> transportHeaders) {

        String contentType = "";
        if (transportHeaders != null) {
            contentType = (String) transportHeaders.get(HTTP.CONTENT_TYPE);
        }
        return contentType;
    }

    /**
     * Build Message and extract payload.
     *
     * @param axis2MC          message context
     * @param contentType      content type of the request
     * @return optional json message
     * @throws JwePayloadProcessingException thrown if unable to build
     */
    public static Optional<String> buildMessagePayloadFromMessageContext(
            org.apache.axis2.context.MessageContext axis2MC, String contentType) throws JwePayloadProcessingException {

        String requestPayload = null;

        boolean isMessageContextBuilt = isMessageContextBuilt(axis2MC);
        if (!isMessageContextBuilt) {
            // Build Axis2 Message.
            try {
                RelayUtils.buildMessage(axis2MC);
            } catch (IOException | XMLStreamException e) {
                throw new JwePayloadProcessingException("Unable to build axis2 message", e);
            }
        }

        if (contentType != null) {
            if (contentType.contains(JwePayloadProcessingConstants.JWE_CONTENT_TYPE)
                    || contentType.contains(JwePayloadProcessingConstants.TEXT_XML_CONTENT_TYPE)
                    || contentType.contains(JwePayloadProcessingConstants.APPLICATION_XML_CONTENT_TYPE)
                    || contentType.contains(JwePayloadProcessingConstants.JWT_CONTENT_TYPE)) {

                OMElement payload = axis2MC.getEnvelope().getBody().getFirstElement();
                if (payload != null) {
                    requestPayload = payload.getText();
                } else {
                    requestPayload = org.apache.commons.lang3.StringUtils.EMPTY;
                }
            } else {
                // Get JSON Stream and cast to string
                try {
                    InputStream jsonPayload = JsonUtil.getJsonPayload(axis2MC);
                    if (jsonPayload != null) {
                        requestPayload = IOUtils.toString(jsonPayload, StandardCharsets.UTF_8.name());
                    }

                } catch (IOException e) {
                    throw new SynapseException("Unable to read payload stream", e);
                }
            }
        }
        return Optional.ofNullable(requestPayload);
    }

    /**
     * Util method to check whether the message context is already built.
     *
     * @param axis2MC axis2 message context
     * @return true if message context is already built
     */
    public static boolean isMessageContextBuilt(org.apache.axis2.context.MessageContext axis2MC) {

        boolean isMessageContextBuilt = false;
        Object messageContextBuilt = axis2MC.getProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED);
        if (messageContextBuilt != null) {
            isMessageContextBuilt = (Boolean) messageContextBuilt;
        }
        return isMessageContextBuilt;
    }

    /**
     * Appends the modified payload to the message context.
     *
     * @param messageContext     Message context
     * @param decryptedPayload   Decrypted payload
     * @param headers            Transport headers
     * @throws JwePayloadProcessingException if an error occurs while appending the modified payload
     */
    public static void setDecryptedPayloadToMessageContext(MessageContext messageContext, JSONObject decryptedPayload,
                                                            Map<String, Object> headers)
            throws JwePayloadProcessingException {

        try {
            org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                    .getAxis2MessageContext();

            // Set the modified payload to the context
            axis2MessageContext.setProperty(Constants.Configuration.MESSAGE_TYPE,
                    MediaType.APPLICATION_JSON);
            axis2MessageContext.setProperty(Constants.Configuration.CONTENT_TYPE,
                    MediaType.APPLICATION_JSON);
            headers.remove(JwePayloadProcessingConstants.CONTENT_TYPE_TAG);
            headers.put(JwePayloadProcessingConstants.CONTENT_TYPE_TAG,
                    JwePayloadProcessingConstants.JSON_CONTENT_TYPE);
            axis2MessageContext.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS,
                    headers);
            JsonUtil.getNewJsonPayload(axis2MessageContext, decryptedPayload.toString(), true, true);
        } catch (AxisFault e) {
            log.error("Error occurred appending the modified payload", e);
            throw new JwePayloadProcessingException("Error occurred appending the modified payload", e);
        }
    }

    /**
     * Retrieves the additional SP properties from the application data JSON.
     * @param applicationDataJson JSONObject containing application data
     * @return JSONArray of additional SP properties, or an empty JSONArray if not found
     */
    public static JSONArray getAdditionalSpProperties(JSONObject applicationDataJson) {

        if (applicationDataJson == null ||
                !applicationDataJson.has(JwePayloadProcessingConstants.ADVANCED_CONFIGURATIONS)) {
            return new JSONArray();
        }

        JSONObject advancedConfigurations = applicationDataJson
                .optJSONObject(JwePayloadProcessingConstants.ADVANCED_CONFIGURATIONS);
        if (advancedConfigurations == null ||
                !advancedConfigurations.has(JwePayloadProcessingConstants.ADDITIONAL_SP_PROPERTIES)) {
            return new JSONArray();
        }

        return advancedConfigurations.optJSONArray(JwePayloadProcessingConstants.ADDITIONAL_SP_PROPERTIES);
    }

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
     * Adds the given encrypted content as the response payload to the given message context.
     *
     * @param content content to be added to the given message context
     * @param messageContext Synapse message context
     */
    public static void addEncryptedPayloadToMessageContext(String content, MessageContext messageContext) {

        org.apache.axis2.context.MessageContext axis2MessageContext =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();

        //Remove existing children from the SOAP body
        removeChildrenFromPayloadBody(axis2MessageContext);

        // Get the OMFactory
        OMFactory omFactory = OMAbstractFactory.getOMFactory();
        // Create a new OMElement with a qualified name (namespace URI and local name)
        // This is the standard way to create a well-formed XML element
        OMElement payloadElement = omFactory.createOMElement(new QName(AXIOMPAYLOADNS, "text"));
        payloadElement.setText(content);
        messageContext.getEnvelope().getBody().addChild(payloadElement);

        axis2MessageContext.setProperty(Constants.Configuration.MESSAGE_TYPE,
                JwePayloadProcessingConstants.PLAIN_TEXT_CONTENT_TYPE);
        axis2MessageContext.setProperty(Constants.Configuration.CONTENT_TYPE,
                JwePayloadProcessingConstants.PLAIN_TEXT_CONTENT_TYPE);
        axis2MessageContext.removeProperty(PassThroughConstants.NO_ENTITY_BODY);
    }

    /**
     * Removes all existing child elements from the SOAP body of the given message context.
     *
     * @param messageContext Axis2 message context
     */
    private static void removeChildrenFromPayloadBody(org.apache.axis2.context.MessageContext messageContext) {

        SOAPEnvelope envelope = messageContext.getEnvelope();
        if (envelope != null) {
            SOAPBody body = envelope.getBody();
            if (body != null) {
                removeChildrenFromSOAPBody(body);
                if (log.isDebugEnabled()) {
                    log.debug("Removed child elements from exiting message. MessageID: " +
                            messageContext.getMessageID());
                }
            }
        }
    }

    /**
     * Removes all child nodes from the given SOAP body.
     *
     * @param body SOAP body from which child nodes should be removed
     */
    private static void removeChildrenFromSOAPBody(SOAPBody body) {

        if (body != null) {
            Iterator children = body.getChildren();

            while (children.hasNext()) {
                Object child = children.next();
                if (child instanceof OMNode) {
                    children.remove();
                }
            }
        }
    }
}
