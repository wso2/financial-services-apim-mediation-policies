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

package org.wso2.financial.services.apim.mediation.policies.jwe.processing.constants;

/**
 * Constants related to JWE Payload Encryption and Decryption.
 */
public class JwePayloadProcessingConstants {

    public static final String CONTENT_TYPE_TAG = "Content-Type";
    public static final String JWE_CONTENT_TYPE = "application/jose+jwe";
    public static final String JSON_CONTENT_TYPE = "application/json";
    public static final String APPLICATION_XML_CONTENT_TYPE = "application/xml";
    public static final String TEXT_XML_CONTENT_TYPE = "text/xml";
    public static final String JWT_CONTENT_TYPE = "application/jwt";
    public static final String PLAIN_TEXT_CONTENT_TYPE = "text/plain";
    public static final String KEYSTORE_LOCATION_CONF_KEY = "Security.KeyStore.Location";
    public static final String KEYSTORE_PASS_CONF_KEY = "Security.KeyStore.Password";
    public static final String JWE_ENCRYPTION_ALG = "jweEncryptionAlg";
    public static final String JWE_ENCRYPTION_METHOD = "jweEncryptionMethod";
    public static final String X509 = "X.509";
    public static final String SHA1 = "SHA-1";

    //Constants for application data retrieval
    public static final String APPLICATION_DATA_PROPERTY = "applicationDataJsonString";
    public static final String ADVANCED_CONFIGURATIONS = "advancedConfigurations";
    public static final String ADDITIONAL_SP_PROPERTIES = "additionalSpProperties";
    public static final String JWS_SP_PROPERTY_KEY = "jwksURI";
}
