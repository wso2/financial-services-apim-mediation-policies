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

package org.wso2.financial.services.apim.mediation.policies.jws.constants;

import java.time.ZoneId;

/**
 * Constants used in JWS Handler.
 */
public class JwsHandlerConstants {

    public static final String SERVER_ERROR_CODE = "500";
    public static final String CONTENT_TYPE_TAG = "Content-Type";
    public static final String JWT_CONTENT_TYPE = "application/jwt";
    public static final String APPLICATION_XML_CONTENT_TYPE = "application/xml";
    public static final String TEXT_XML_CONTENT_TYPE = "text/xml";
    public static final String APPLICATION_OCTET_STREAM_TYPE = "application/octet-stream";
    public static final String GET_HTTP_METHOD = "GET";
    public static final String HTTP_METHOD = "api.ut.HTTP_METHOD";
    public static final String API_ELECTED_RESOURCE = "API_ELECTED_RESOURCE";
    public static final String KEYSTORE_LOCATION_CONF_KEY = "Security.KeyStore.Location";
    public static final String KEYSTORE_PASS_CONF_KEY = "Security.KeyStore.Password";
    public static final String UK_API_V4_PATH = "4.0";
    public static final String FILE_PAYMENT_CONSENTS_FILE = "/file-payment-consents/{ConsentId}/file";
    public static final String FILE_PAYMENT_REPORT_FILE = "/file-payments/{FilePaymentId}/report-file";
    public static final String VERSION_PREFIX = "v";
    public static final ZoneId ZONE_ID = ZoneId.of("GMT");

    // Error Response Structure constants
    public static final String CODE = "Code";
    public static final String ID = "Id";
    public static final String MESSAGE = "Message";
    public static final String ERRORS = "Errors";
    public static final String ERROR_CODE = "ErrorCode";
    public static final String PATH = "Path";
    public static final String SIGNATURE_UNEXPECTED = "UK.OBIE.Signature.Unexpected";
    public static final String U020 = "U020";
    public static final String INTERNAL_SERVER_ERROR = "Internal server error";

    // Claims
    public static final String IAT_CLAIM_KEY = "http://openbanking.org.uk/iat";
    public static final String ISS_CLAIM_KEY = "http://openbanking.org.uk/iss";
    public static final String TAN_CLAIM_KEY = "http://openbanking.org.uk/tan";
    public static final String B64_CLAIM_KEY = "b64";

}
