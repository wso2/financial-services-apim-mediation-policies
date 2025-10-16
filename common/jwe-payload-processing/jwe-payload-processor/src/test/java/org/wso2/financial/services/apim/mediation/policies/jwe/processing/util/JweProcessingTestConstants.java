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

/**
 * Constants used in JWE processing.
 */
public class JweProcessingTestConstants {

    public static final String PAYLOAD = "{" +
            "   \"Data\":{" +
            "       \"Permissions\":[" +
            "           \"ReadAccountsBasic\"," +
            "           \"ReadAccountsDetail\"," +
            "           \"ReadBalances\"," +
            "           \"ReadTransactionsDetail\"" +
            "       ]," +
            "       \"TransactionToDateTime\":\"2025-10-12T13:56:05.792536+05:30\"," +
            "       \"ExpirationDateTime\":\"2025-10-14T13:56:05.791491+05:30\"," +
            "       \"TransactionFromDateTime\":\"2025-10-09T13:56:05.792426+05:30\"" +
            "   }," +
            "   \"Risk\":{}" +
            "}";

    public static final String JWK = "{\n" +
            "    \"kid\" : \"qGSq26Iezcl8OuSDV89JiKAYDuY\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"uelFrqWTaddV1c96pcme8lbaJ5MAHdoqEkFcc9Z7ICQC4y5k2QIbvnsIO3h301FZtejI47V" +
            "           sd7ikrg3VvDEDM9_qODxl_--E6g58AatVLYalUcZo04dxWjilEj3Cd8Mdsoz2vGUGi7Jc7UnZH" +
            "           JckcRo-83P46P3SOtEDkEdtH6wVQzWAYBP2CkuOPZphnt9d3trtznjDdt0TPc54RUNaPjn_4CU" +
            "           RH9Dc6bQ60TuObT2Ss2dbkJLvWcKEsPi3OGt8FxCW8HagokFnf8y0xIBagtghdCcWjbvEMDsfO" +
            "           e8lcp7H4u6cluJ9bu9w6_MvIfKi16Sz8n9vws2Gei8ivudaCQ\",\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"use\" : \"enc\"\n" +
            "  }";
}
