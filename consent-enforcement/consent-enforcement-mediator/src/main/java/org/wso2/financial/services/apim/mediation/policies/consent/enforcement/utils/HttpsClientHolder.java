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

package org.wso2.financial.services.apim.mediation.policies.consent.enforcement.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.IOException;

/**
 * Class to hold HTTPS client configurations.
 */
public class HttpsClientHolder {

    private static final Log log = LogFactory.getLog(HttpsClientHolder.class);
    private static final CloseableHttpClient INSTANCE;

    static {

        INSTANCE = HttpClients.createDefault();

        // Optional: Add shutdown hook to clean up properly
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                INSTANCE.close();
            } catch (IOException e) {
                log.error("Error shutting down HttpClient", e);
            }
        }));

        log.debug("HTTPS Client initialized with singleton pattern.");
    }

    public static CloseableHttpClient getHttpsClient() {

        return HttpsClientHolder.INSTANCE;
    }

}
