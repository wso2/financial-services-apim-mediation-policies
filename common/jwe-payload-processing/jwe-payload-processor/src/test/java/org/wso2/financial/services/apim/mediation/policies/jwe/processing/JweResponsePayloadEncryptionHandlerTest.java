package org.wso2.financial.services.apim.mediation.policies.jwe.processing;

import com.nimbusds.jose.jwk.JWK;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.transport.nhttp.NhttpConstants;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.constants.JwePayloadProcessingConstants;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.util.JweProcessingTestConstants;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.util.JweProcessingTestUtil;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.util.JwkUtils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertTrue;

public class JweResponsePayloadEncryptionHandlerTest {

    private JweResponsePayloadEncryptionHandler handler;
    private MessageContext synapseCtx;
    private Axis2MessageContext axis2Ctx;
    private Map<String, Object> headers;

    MockedStatic<RelayUtils> relayUtilsMockedStatic;
    MockedStatic<JsonUtil> jsonUtilMockedStatic;
    MockedStatic<JwkUtils> jwkUtilsMockedStatic;

    @BeforeClass
    public void setup() {
        handler = new JweResponsePayloadEncryptionHandler();
        synapseCtx = mock(MessageContext.class);
        axis2Ctx = mock(Axis2MessageContext.class);
        axis2Ctx.setProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED, true);
        headers = new HashMap<>();
        when(axis2Ctx.getAxis2MessageContext()).thenReturn(synapseCtx);

        relayUtilsMockedStatic = mockStatic(RelayUtils.class);
        relayUtilsMockedStatic.when(() -> RelayUtils.buildMessage(synapseCtx, true))
                .thenAnswer(invocation -> null);
        jsonUtilMockedStatic = mockStatic(JsonUtil.class);
        jwkUtilsMockedStatic = mockStatic(JwkUtils.class);

    }

    @AfterClass
    public void tearDown() {
        relayUtilsMockedStatic.close();
        jsonUtilMockedStatic.close();
        jwkUtilsMockedStatic.close();
    }

    @Test
    public void testEncryptionNotApplicableScenarios() {

        headers.put("Content-Type", "application/json");
        when(synapseCtx.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(headers);
        when(synapseCtx.getProperty(NhttpConstants.HTTP_SC)).thenReturn(400);

        boolean result = handler.handleResponseOutFlow(axis2Ctx);

        assertTrue(result, "Handler should successfully encrypt the payload.");
    }

    @Test(dataProviderClass = JweProcessingTestUtil.class, dataProvider = "encryptionData")
    public void testEncryption(String encAlg, String encMethod) {

        headers.put("Content-Type", "application/json");
        when(synapseCtx.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(headers);
        when(synapseCtx.getProperty(NhttpConstants.HTTP_SC)).thenReturn(200);
        when(synapseCtx.getProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED)).thenReturn(true);
        when(axis2Ctx.getProperty(JwePayloadProcessingConstants.JWE_ENCRYPTION_ALG)).thenReturn(encAlg);
        when(axis2Ctx.getProperty(JwePayloadProcessingConstants.JWE_ENCRYPTION_METHOD)).thenReturn(encMethod);

        JSONObject appData = new JSONObject();
        JSONArray spProperties = new JSONArray();
        JSONObject jwksProperty = new JSONObject();
        jwksProperty.put("name", JwePayloadProcessingConstants.JWS_SP_PROPERTY_KEY);
        jwksProperty.put("value",
                "https://keystore.openbankingtest.org.uk/0015800001HQQrZAAX/oQ4KoaavpOuoE7rvQsZEOV.jwks");
        spProperties.put(jwksProperty);
        appData.put(JwePayloadProcessingConstants.ADVANCED_CONFIGURATIONS, new JSONObject()
                .put(JwePayloadProcessingConstants.ADDITIONAL_SP_PROPERTIES, spProperties));
        when(axis2Ctx.getProperty(JwePayloadProcessingConstants.APPLICATION_DATA_PROPERTY))
                .thenReturn(appData.toString());

        JWK encryptionJwk = mock(JWK.class);
        doReturn(JweProcessingTestConstants.JWK).when(encryptionJwk).toJSONString();
        jwkUtilsMockedStatic.when(() -> JwkUtils.getEncryptionJWKFromJWKS(anyString(), any()))
                .thenReturn(encryptionJwk);
        jwkUtilsMockedStatic.when(() -> JwkUtils.getKidValueFromJwk(any(JWK.class)))
                .thenReturn("qGSq26Iezcl8OuSDV89JiKAYDuY");

        Iterator iterator = mock(Iterator.class);
        SOAPBody body = mock(SOAPBody.class);
        doReturn(iterator).when(body).getChildren();
        SOAPEnvelope envelope = mock(SOAPEnvelope.class);
        doReturn(body).when(envelope).getBody();
        when(synapseCtx.getEnvelope()).thenReturn(envelope);
        when(axis2Ctx.getEnvelope()).thenReturn(envelope);

        InputStream mockInputStream = new ByteArrayInputStream(JweProcessingTestConstants.PAYLOAD
                .getBytes(StandardCharsets.UTF_8));
        jsonUtilMockedStatic.when(() -> JsonUtil.getJsonPayload(synapseCtx))
                .thenReturn(mockInputStream);

        boolean result = handler.handleResponseOutFlow(axis2Ctx);

        assertTrue(result, "Handler should successfully encrypt the payload.");
    }
}
