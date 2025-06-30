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

package org.wso2.financial.services.apim.mediation.policies.jws.header.processing.constants;

/**
 * Constants for JWS (JSON Web Signature) related operations.
 */
public class JwsConstants {

    public static final String CONTENT_TYPE_TAG = "Content-Type";
    public static final String JWT_CONTENT_TYPE = "application/jwt";
    public static final String APPLICATION_XML_CONTENT_TYPE = "application/xml";
    public static final String TEXT_XML_CONTENT_TYPE = "text/xml";
    public static final String ISS_FORMAT = "^([a-zA-Z0-9]{0,})\\/([a-zA-Z0-9]{0,})$";
    public static final String APPLICATION_JSON = "application/json";
    public static final String JSON = "json";
    public static final String REST_FULL_REQUEST_PATH = "REST_FULL_REQUEST_PATH";
    public static final String HTTP_METHOD = "api.ut.HTTP_METHOD";

    // Claims
    public static final String IAT_CLAIM_KEY = "http://openbanking.org.uk/iat";
    public static final String ISS_CLAIM_KEY = "http://openbanking.org.uk/iss";
    public static final String TAN_CLAIM_KEY = "http://openbanking.org.uk/tan";
    public static final String B64_CLAIM_KEY = "b64";
    public static final String KID_CLAIM_KEY = "kid";
    public static final String CRIT_CLAIM_KEY = "crit";
    public static final String TYP_CLAIM_KEY = "typ";
    public static final String CTY_CLAIM_KEY = "cty";
    public static final String ALG_CLAIM_KEY = "alg";

    // JSON constants
    public static final String APPLICATION_DATA_PROPERTY = "applicationDataJsonString";
    public static final String ADVANCED_CONFIGURATIONS = "advancedConfigurations";
    public static final String ADDITIONAL_SP_PROPERTIES = "additionalSpProperties";
    public static final String JWS_SP_PROPERTY_KEY = "jwksURI";

    // Error constants
    public static final String ERROR_CODE = "ERROR_CODE";
    public static final String ERROR_TITLE = "ERROR_TITLE";
    public static final String ERROR_DESCRIPTION = "ERROR_DESCRIPTION";
    public static final String CUSTOM_HTTP_SC = "CUSTOM_HTTP_SC";

}
