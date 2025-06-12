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

package org.wso2.financial.services.apim.mediation.policies.mtls.enforcement;

import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.wso2.financial.services.apim.mediation.policies.mtls.enforcement.utils.MTLSEnforcementUtils;

import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Map;

/**
 * Mediator to enforce MTLS as a header in the request.
 */
public class MTLSHeaderEnforcementMediator extends AbstractMediator {

    private String transportCertHeaderName;
    private boolean isClientCertificateEncoded;

    @Override
    public boolean mediate(MessageContext messageContext) {

        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        Map<String, String> headers = (Map<String, String>)
                axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        String certificateHeaderValue = headers.get(transportCertHeaderName);

        try {
            Certificate certificate = MTLSEnforcementUtils
                    .getClientCertificateFromHeader(certificateHeaderValue, isClientCertificateEncoded);
            if (certificate == null) {
                // TODO: handle error properly
                return false;
            }
        } catch (UnsupportedEncodingException e) {
            // TODO: handle error properly
            return false;
        } catch (CertificateException e) {
            // TODO: handle error properly
            return false;
        }

        return true;
    }

    public String getTransportCertHeaderName() {
        return transportCertHeaderName;
    }

    public void setTransportCertHeaderName(String transportCertHeaderName) {
        this.transportCertHeaderName = transportCertHeaderName;
    }

    public boolean isClientCertificateEncoded() {
        return isClientCertificateEncoded;
    }

    public void setIsClientCertificateEncoded(boolean isClientCertificateEncoded) {
        this.isClientCertificateEncoded = isClientCertificateEncoded;
    }
}
