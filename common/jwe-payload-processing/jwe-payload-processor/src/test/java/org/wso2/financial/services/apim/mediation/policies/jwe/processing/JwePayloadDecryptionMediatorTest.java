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

import com.nimbusds.jose.JOSEException;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.synapse.SynapseException;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.util.JweProcessingTestConstants;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.util.JweProcessingTestUtil;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.util.ServerKeystoreRetriever;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertTrue;

public class JwePayloadDecryptionMediatorTest {

    private JwePayloadDecryptionMediator mediator;
    private MessageContext synapseCtx;
    private Axis2MessageContext axis2Ctx;
    private Map<String, Object> headers;

    MockedStatic<ServerKeystoreRetriever> serverKeystoreRetrieverMockedStatic;
    MockedStatic<RelayUtils> relayUtilsMockedStatic;
    MockedStatic<JsonUtil> jsonUtilMockedStatic;

    @BeforeClass
    public void setup() {
        mediator = new JwePayloadDecryptionMediator();
        synapseCtx = mock(MessageContext.class);
        axis2Ctx = mock(Axis2MessageContext.class);
        axis2Ctx.setProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED, true);
        headers = new HashMap<>();
        when(axis2Ctx.getAxis2MessageContext()).thenReturn(synapseCtx);

        serverKeystoreRetrieverMockedStatic = mockStatic(ServerKeystoreRetriever.class);
        relayUtilsMockedStatic = mockStatic(RelayUtils.class);
        relayUtilsMockedStatic.when(() -> RelayUtils.buildMessage(synapseCtx, true))
                .thenAnswer(invocation -> null);
        jsonUtilMockedStatic = mockStatic(JsonUtil.class);
    }

    @AfterClass
    public void tearDown() {
        serverKeystoreRetrieverMockedStatic.close();
        relayUtilsMockedStatic.close();
        jsonUtilMockedStatic.close();
    }

    @Test
    public void testUnsupportedContentType() {
        headers.put("Content-Type", "application/json");
        when(synapseCtx.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(headers);

        boolean result = mediator.mediate(axis2Ctx);

        assertTrue(result, "Mediator should skip decryption for unsupported content types.");
    }

    @Test(expectedExceptions = SynapseException.class)
    public void testMissingPrivateKey() throws JOSEException {
        headers.put("Content-Type", "application/jose+jwe");
        when(synapseCtx.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(headers);

        String encryptedPayload = JweProcessingTestUtil.encryptPayload("RSA-OAEP-256", "A256GCM",
                JweProcessingTestConstants.PAYLOAD);
        ServerKeystoreRetriever serverKeystoreRetriever = mock(ServerKeystoreRetriever.class);
        when(serverKeystoreRetriever.getSigningKey(anyString()))
                .thenReturn(JweProcessingTestUtil.getSigningKey("src/test/resources/sample-keystore.jks",
                        "wso2carbon", "wso2carbon"));
        serverKeystoreRetrieverMockedStatic.when(ServerKeystoreRetriever::getInstance)
                .thenReturn(serverKeystoreRetriever);

        OMElement omElement = mock(OMElement.class);
        doReturn(encryptedPayload).when(omElement).getText();
        SOAPBody body = mock(SOAPBody.class);
        doReturn(null).when(body).getFirstElement();
        SOAPEnvelope envelope = mock(SOAPEnvelope.class);
        doReturn(body).when(envelope).getBody();
        when(synapseCtx.getEnvelope()).thenReturn(envelope);
        when(axis2Ctx.getEnvelope()).thenReturn(envelope);

        InputStream mockInputStream = new ByteArrayInputStream(JweProcessingTestConstants.PAYLOAD
                .getBytes(StandardCharsets.UTF_8));
        jsonUtilMockedStatic.when(() -> JsonUtil.getJsonPayload(synapseCtx))
                .thenReturn(mockInputStream);

        mediator.mediate(axis2Ctx);
    }

    @Test(expectedExceptions = SynapseException.class)
    public void testEmptyPayload() {
        headers.put("Content-Type", "application/jose+jwe");
        when(synapseCtx.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(headers);
        when(synapseCtx.getProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED)).thenReturn(true);

        ServerKeystoreRetriever serverKeystoreRetriever = mock(ServerKeystoreRetriever.class);
        when(serverKeystoreRetriever.getSigningKey(anyString()))
                .thenReturn(JweProcessingTestUtil.getSigningKey("src/test/resources/wso2carbon.jks",
                        "wso2carbon", "wso2carbon"));
        serverKeystoreRetrieverMockedStatic.when(ServerKeystoreRetriever::getInstance)
                .thenReturn(serverKeystoreRetriever);

        SOAPBody body = mock(SOAPBody.class);
        doReturn(null).when(body).getFirstElement();
        SOAPEnvelope envelope = mock(SOAPEnvelope.class);
        doReturn(body).when(envelope).getBody();
        when(synapseCtx.getEnvelope()).thenReturn(envelope);
        when(axis2Ctx.getEnvelope()).thenReturn(envelope);

        mediator.mediate(axis2Ctx);
    }

    @Test(expectedExceptions = SynapseException.class)
    public void testDecryptionWithInvalidJwe() {

        headers.put("Content-Type", "application/jose+jwe");
        when(synapseCtx.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(headers);

        ServerKeystoreRetriever serverKeystoreRetriever = mock(ServerKeystoreRetriever.class);
        when(serverKeystoreRetriever.getSigningKey(anyString()))
                .thenReturn(JweProcessingTestUtil.getSigningKey("src/test/resources/wso2carbon.jks",
                        "wso2carbon", "wso2carbon"));
        serverKeystoreRetrieverMockedStatic.when(ServerKeystoreRetriever::getInstance)
                .thenReturn(serverKeystoreRetriever);

        OMElement omElement = mock(OMElement.class);
        doReturn("qwyeonoqwib").when(omElement).getText();
        SOAPBody body = mock(SOAPBody.class);
        doReturn(null).when(body).getFirstElement();
        SOAPEnvelope envelope = mock(SOAPEnvelope.class);
        doReturn(body).when(envelope).getBody();
        when(synapseCtx.getEnvelope()).thenReturn(envelope);
        when(axis2Ctx.getEnvelope()).thenReturn(envelope);

        mediator.mediate(axis2Ctx);
    }

    @Test(dataProviderClass = JweProcessingTestUtil.class, dataProvider = "encryptionData")
    public void testSuccessfulDecryption(String encAlg, String encMethod) throws JOSEException {

        headers.put("Content-Type", "application/jose+jwe");
        when(synapseCtx.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(headers);

        String encryptedPayload = JweProcessingTestUtil.encryptPayload(encAlg, encMethod,
                JweProcessingTestConstants.PAYLOAD);

        ServerKeystoreRetriever serverKeystoreRetriever = mock(ServerKeystoreRetriever.class);
        when(serverKeystoreRetriever.getSigningKey(anyString()))
                .thenReturn(JweProcessingTestUtil.getSigningKey("src/test/resources/wso2carbon.jks",
                        "wso2carbon", "wso2carbon"));
        serverKeystoreRetrieverMockedStatic.when(ServerKeystoreRetriever::getInstance)
                .thenReturn(serverKeystoreRetriever);
//        jweUtilsMockedStatic.when(() -> JwePayloadProcessingUtils.getContentType(anyMap()))
//                .thenReturn("application/jose+jwe");
//        jweUtilsMockedStatic.when(() -> JwePayloadProcessingUtils.isSupportedContentType(anyString()))
//                .thenReturn(true);
//        jweUtilsMockedStatic.when(() -> JwePayloadProcessingUtils.buildMessagePayloadFromMessageContext(any(),
//                        anyString())).thenReturn(Optional.of(encryptedPayload));
//        jweUtilsMockedStatic.when(() -> JwePayloadProcessingUtils.setDecryptedPayloadToMessageContext(any(), any(),
//                anyMap())).thenAnswer(invocation -> null);

        OMElement omElement = mock(OMElement.class);
        doReturn(encryptedPayload).when(omElement).getText();
        SOAPBody body = mock(SOAPBody.class);
        doReturn(omElement).when(body).getFirstElement();
        SOAPEnvelope envelope = mock(SOAPEnvelope.class);
        doReturn(body).when(envelope).getBody();
        when(synapseCtx.getEnvelope()).thenReturn(envelope);
        when(axis2Ctx.getEnvelope()).thenReturn(envelope);

        boolean result = mediator.mediate(axis2Ctx);

        assertTrue(result, "Mediator should successfully decrypt the payload.");
    }
}
