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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import org.apache.synapse.SynapseException;
import org.testng.annotations.DataProvider;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;

/**
 * Test utility class for JWE processing.
 */
public class JweProcessingTestUtil {

    public static String encryptPayload(String encryptionAlg, String encryptionMethod, String payload)
            throws JOSEException {


        try (FileInputStream is = new FileInputStream("src/test/resources/wso2carbon.jks")) {

            // 1. Get the public RSA key from the keystore
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, "wso2carbon".toCharArray());
            Certificate publicKey = keystore.getCertificate("wso2carbon");
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey.getPublicKey();

            JWEAlgorithm jweAlg = JWEAlgorithm.parse(encryptionAlg);
            EncryptionMethod encMethod = EncryptionMethod.parse(encryptionMethod);
            JWEHeader header = new JWEHeader.Builder(jweAlg, encMethod)
                    .build();
            Payload payloadData = new Payload(payload);
            JWEObject jweObject = new JWEObject(header, payloadData);
            RSAEncrypter encrypter = new RSAEncrypter(rsaPublicKey);
            jweObject.encrypt(encrypter);
            return jweObject.serialize();
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            return null;
        }
    }

    public static Key getSigningKey(String keyStoreLocation, String keyStorePassword, String alias)
            throws SynapseException  {

        try (FileInputStream inputStream = new FileInputStream(keyStoreLocation)) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(inputStream, keyStorePassword.toCharArray());
            return keyStore.getKey(alias, keyStorePassword.toCharArray());
        } catch (KeyStoreException | UnrecoverableKeyException e) {
            throw new SynapseException("Error while retrieving aliases from keystore: " + keyStoreLocation, e);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new SynapseException("Error while loading keystore", e);
        }
    }

    @DataProvider(name = "encryptionData")
    public Object[][] getEncryptionData() {

        return new Object[][] {
                {"RSA-OAEP-256", "A128GCM"}, {"RSA-OAEP-256", "A256GCM"}, {"RSA-OAEP-256", "A192GCM"},

                {"RSA-OAEP", "A128GCM"}, {"RSA-OAEP", "A256GCM"}, {"RSA-OAEP", "A192GCM"},

                {"RSA-OAEP-384", "A128GCM"}, {"RSA-OAEP-384", "A256GCM"}, {"RSA-OAEP-384", "A192GCM"},

                {"RSA-OAEP-512", "A128GCM"}, {"RSA-OAEP-512", "A256GCM"}, {"RSA-OAEP-512", "A192GCM"},

                {"RSA1_5", "A128GCM"}, {"RSA1_5", "A256GCM"}, {"RSA1_5", "A192GCM"}
        };
    }
}
