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

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.exceptions.JwePayloadProcessingException;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.util.JwkUtils;

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/**
 * Test class for JwkUtils.
 */
public class JwkUtilsTest {

    private static final String JWKS_URI = "https://example.com/jwks";
    private static final JWEAlgorithm ENCRYPTION_ALGORITHM = JWEAlgorithm.RSA_OAEP_256;

    @Test
    public void testGetEncryptionJWKFromJWKS() {
        // Mock JWKSet and JWK
        JWK mockJwk = mock(JWK.class);
        JWKSet mockJwkSet = mock(JWKSet.class);

        try (MockedStatic<JWKSet> mockedJwkSet = Mockito.mockStatic(JWKSet.class);
             MockedConstruction<JWKSelector> mockedJwkSelector = Mockito.mockConstruction(JWKSelector.class,
                (mock, context) -> {
                    when(mock.select(mockJwkSet)).thenReturn(Collections.singletonList(mockJwk));
                })) {

            when(mockJwkSet.getKeys()).thenReturn(Collections.singletonList(mockJwk));
            when(mockJwk.getAlgorithm()).thenReturn(ENCRYPTION_ALGORITHM);
            mockedJwkSet.when(() -> JWKSet.load(any(URL.class))).thenReturn(mockJwkSet);

            JWK result = JwkUtils.getEncryptionJWKFromJWKS(JWKS_URI, ENCRYPTION_ALGORITHM);

            assertNotNull(result);
            assertEquals(mockJwk, result);
        }
    }

    @Test(expectedExceptions = JwePayloadProcessingException.class)
    public void testGetEncryptionJWKFromJWKSWithEmptyKeys() {
        // Mock JWKSet and JWK
        JWK mockJwk = mock(JWK.class);
        JWKSet mockJwkSet = mock(JWKSet.class);

        try (MockedStatic<JWKSet> mockedJwkSet = Mockito.mockStatic(JWKSet.class);
             MockedConstruction<JWKSelector> mockedJwkSelector = Mockito.mockConstruction(JWKSelector.class,
                     (mock, context) -> {
                         when(mock.select(mockJwkSet)).thenReturn(Collections.emptyList());
                     })) {

            when(mockJwk.getAlgorithm()).thenReturn(ENCRYPTION_ALGORITHM);
            mockedJwkSet.when(() -> JWKSet.load(any(URL.class))).thenReturn(mockJwkSet);

            JWK result = JwkUtils.getEncryptionJWKFromJWKS(JWKS_URI, ENCRYPTION_ALGORITHM);

            assertNotNull(result);
            assertEquals(mockJwk, result);
        }
    }

    @Test(expectedExceptions = JwePayloadProcessingException.class)
    public void testGetEncryptionJWKFromJWKSWithLoadingError() {
        try (MockedStatic<JWKSet> mockedJwkSet = Mockito.mockStatic(JWKSet.class)) {
            mockedJwkSet.when(() -> JWKSet.load(new URL(JWKS_URI)))
                    .thenThrow(new ParseException("Error loading JWKSet", 0));

            JwkUtils.getEncryptionJWKFromJWKS(JWKS_URI, ENCRYPTION_ALGORITHM);
        }
    }

    @Test
    public void testGetKidValueFromJwkWithKeyID() {
        JWK mockJwk = mock(JWK.class);
        when(mockJwk.getKeyID()).thenReturn("test-kid");

        String kid = JwkUtils.getKidValueFromJwk(mockJwk);

        assertEquals(kid, "test-kid");
    }

    @Test
    public void testGetKidValueFromJwkWithoutKeyID() {
        JWK mockJwk = mock(JWK.class);
        when(mockJwk.getKeyID()).thenReturn(null);
        X509Certificate mockCertificate = mock(X509Certificate.class);
        when(mockJwk.getParsedX509CertChain()).thenReturn(Collections.singletonList(mockCertificate));

        try (MockedStatic<JwkUtils> mockedJwkUtils = Mockito.mockStatic(JwkUtils.class)) {
            mockedJwkUtils.when(() -> JwkUtils.getJwkThumbPrint(mockCertificate)).thenReturn("thumbprint");

            String kid = JwkUtils.getKidValueFromJwk(mockJwk);

            assertNull(kid);
        }
    }

    @Test
    public void testGetJwkThumbPrint() throws Exception {

        // Mock the certificate
        Certificate mockCertificate = mock(Certificate.class);
        byte[] encodedCertificate = new byte[]{0x01, 0x02, 0x03};
        when(mockCertificate.getEncoded()).thenReturn(encodedCertificate);

        // Mock the CertificateFactory
        CertificateFactory mockCertificateFactory = mock(CertificateFactory.class);
        X509Certificate mockX509Certificate = mock(X509Certificate.class);
        when(mockCertificateFactory.generateCertificate(any(ByteArrayInputStream.class)))
                .thenReturn(mockX509Certificate);

        // Mock the RSAKey.parse and computeThumbprint
        Base64URL mockThumbprint = mock(Base64URL.class);
        when(mockThumbprint.toString()).thenReturn("mocked-thumbprint");
        try (MockedStatic<RSAKey> mockedRsaKey = Mockito.mockStatic(RSAKey.class);
             MockedStatic<CertificateFactory> mockedCertFactory = Mockito.mockStatic(CertificateFactory.class)) {

            mockedCertFactory.when(() -> CertificateFactory.getInstance("X.509"))
                    .thenReturn(mockCertificateFactory);
            mockedRsaKey.when(() -> RSAKey.parse(mockX509Certificate)).thenReturn(mock(RSAKey.class));
            mockedRsaKey.when(() -> RSAKey.parse(mockX509Certificate).computeThumbprint("SHA-1"))
                    .thenReturn(mockThumbprint);

            // Call the method under test
            String thumbprint = JwkUtils.getJwkThumbPrint(mockCertificate);

            // Assertions
            assertNotNull(thumbprint);
            assertEquals(thumbprint, "mocked-thumbprint");
        }
    }

    @Test
    public void testGetPublicCertFromJWK() {
        // Mock JWK and X509Certificate
        JWK mockJwk = mock(JWK.class);
        X509Certificate mockCertificate = mock(X509Certificate.class);

        // Define behavior for the mocked JWK
        when(mockJwk.getParsedX509CertChain()).thenReturn(Collections.singletonList(mockCertificate));

        // Call the method under test
        X509Certificate result = JwkUtils.getPublicCertFromJWK(mockJwk);

        // Assertions
        assertNotNull(result);
        assertEquals(mockCertificate, result);
    }

    @Test(expectedExceptions = JwePayloadProcessingException.class)
    public void testGetPublicCertFromJWKWithNullJWK() {
        // Call the method with a null JWK
        JwkUtils.getPublicCertFromJWK(null);
    }

    @Test(expectedExceptions = JwePayloadProcessingException.class)
    public void testGetPublicCertFromJWKWithNullCertChain() {
        // Mock JWK with null certificate chain
        JWK mockJwk = mock(JWK.class);
        when(mockJwk.getParsedX509CertChain()).thenReturn(null);

        // Call the method under test
        JwkUtils.getPublicCertFromJWK(mockJwk);
    }
}
