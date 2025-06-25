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

package org.wso2.financial.services.apim.mediation.policies.jws;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseException;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.financial.services.apim.mediation.policies.jws.constants.JwsConstants;
import org.wso2.financial.services.apim.mediation.policies.jws.utils.JwsUtils;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.ws.rs.HttpMethod;

/**
 * Mediator for validating JWS request headers.
 */
public class JwsRequestHeaderValidationMediator extends AbstractMediator {

    private static final Log log = LogFactory.getLog(JwsRequestHeaderValidationMediator.class);

    private String jwSignatureHeaderName;
    private String validTrustAnchor = null;
    private String jwsSupportedAlgorithms = null;

    /**
     * JWK retrieved from JwksURI matching to the KeyID.
     */
    private JWK matchingJWK = null;

    @Override
    public boolean mediate(MessageContext messageContext) {

        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        Map<String, String> headers = (Map<String, String>)
                axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        String payload = JwsUtils.extractPayload(axis2MessageContext, headers);
        String jwSignature = headers.get(jwSignatureHeaderName);

        String restFullRequestPath = (String) messageContext.getProperty(JwsConstants.REST_FULL_REQUEST_PATH);
        String httpMethod = (String) messageContext.getProperty(JwsConstants.HTTP_METHOD);

        // For logging purposes
        String pathWithMethod = restFullRequestPath + ":" + httpMethod;

        if (StringUtils.isEmpty(jwSignature)) {
            String errorDescription = "Empty JWS Signature";
            log.error(errorDescription + ". for request: " + pathWithMethod);
            setErrorResponseProperties(messageContext, "Bad Request", errorDescription, "400");
            throw new SynapseException(errorDescription);
        }

        JSONObject applicationDataJson = new JSONObject((String) messageContext
                .getProperty(JwsConstants.APPLICATION_DATA_PROPERTY));

        JSONArray additionalSpProperties = JwsUtils.getAdditionalSpProperties(applicationDataJson);
        String jwksUrl = JwsUtils.getAdditionalSpProperty(additionalSpProperties, JwsConstants.JWS_SP_PROPERTY_KEY);

        /*
        Check if the payload is blank or matches an empty string ("").
        If the REST method is POST or PUT, it indicates that the payload is required for these methods.
         */
        if (StringUtils.isBlank(payload) || payload.matches("\"\"")) {
            String restMethod = (String) messageContext.getProperty("REST_METHOD");
            if (HttpMethod.POST.equals(restMethod) || HttpMethod.PUT.equals(restMethod)) {
                String errorDescription = "Request payload cannot be empty";
                log.error(errorDescription + ". for request: " + pathWithMethod);
                setErrorResponseProperties(messageContext, "Bad Request", errorDescription, "400");
                throw new SynapseException(errorDescription);
            }
        }

        boolean verified;
        try {
            verified = validateDetachedJWS(messageContext, jwSignature, payload, jwksUrl);

            if (!verified) {
                String errorDescription = "Invalid JWS Signature";
                log.error(errorDescription + ". for request: " + pathWithMethod);
                setErrorResponseProperties(messageContext, "Bad Request", errorDescription, "400");
                throw new SynapseException(errorDescription);
            }

            return true;
        } catch (IOException | ParseException | JOSEException | SynapseException e) {
            log.error(e.getMessage() + ". for request: " + pathWithMethod, e);
            setErrorResponseProperties(messageContext, "Bad Request", e.getMessage(), "400");
            throw new SynapseException(e.getMessage());
        }
    }

    /**
     * Validates a detached JWS signature against the provided payload and JWKS URL.
     *
     * @param messageContext The Synapse MessageContext
     * @param detachedJWS The detached JWS signature in the format <header>..<signature>
     * @param payload The payload to verify against the detached JWS signature
     * @param jwksUrl The URL of the JWKS endpoint to retrieve the public key for verification
     * @return true if the detached JWS signature is valid, false otherwise
     * @throws ParseException
     * @throws JOSEException
     * @throws IOException
     */
    protected boolean validateDetachedJWS(MessageContext messageContext, String detachedJWS, String payload,
                                          String jwksUrl) throws ParseException, JOSEException, IOException {

        String[] parts = detachedJWS.split("\\.");
        if (parts.length != 3) {
            throw new SynapseException("Invalid detached JWS format. Expected format: <header>..<signature>");
        }

        Base64URL encodedHeader = new Base64URL(parts[0]);
        Base64URL encodedSignature = new Base64URL(parts[2]);

        // Parse JWS header
        JWSHeader jwsHeader = JWSHeader.parse(encodedHeader);

        PublicKey publicKey = getPublicKeyFromJWKS(jwksUrl, jwsHeader.getKeyID());

        // Create custom critical header policy
        Set<String> deferredCritHeaders = JwsUtils.getDifferedCritHeaders();

        boolean areCustomClaimsValid = validateCustomClaims(messageContext, jwsHeader, jwksUrl);

        if (!areCustomClaimsValid) {
            return false;
        }

        JWSVerifier verifier = JwsUtils.getJwsVerifier(publicKey, jwsHeader, deferredCritHeaders);

        if (JwsUtils.isPayloadB64Encoded(jwsHeader)) {
            // b64=true
            log.debug("Reconstructing the JWS by base64 encoding the payload");

            String reconstructedJws = JwsUtils.reconstructJws(detachedJWS, payload);
            JWSObject jwsObject = JWSObject.parse(reconstructedJws);
            return jwsObject.verify(verifier);
        } else {
            // b64=false (raw payload used in signature input)
            // Construct the signing input: base64url(header) + "." + payload
            log.debug("Reconstructing the JWS using the raw payload bytes");

            String signingInput = encodedHeader + "." + payload;
            byte[] signingInputBytes = signingInput.getBytes(StandardCharsets.US_ASCII);
            return verifier.verify(jwsHeader, signingInputBytes, encodedSignature);
        }
    }

    /**
     * Validates custom claims in the JWS header.
     *
     * @param messageContext The Synapse MessageContext
     * @param jwsHeader JWSHeader containing the claims to validate
     * @param jwksURI JwksURL to retrieve the public key for verification
     * @return true if the custom claims are valid, false otherwise
     */
    protected boolean validateCustomClaims(MessageContext messageContext, JWSHeader jwsHeader, String jwksURI) {

        // typ Validation. If specified, verify if it has the value JOSE.
        if (!validateTypeClaim(jwsHeader)) {
            throw new SynapseException("Error occurred due to invalid type");
        }

        // allowed claims in sorted array.
        // If the claim set has a claim not in allowedClaims handle error.
        validateAllowedClaims(jwsHeader);

        // Alg Validation. Validates specified algorithm.
        List<String> jwsSupportedAlgs = getJwsSupportedAlgorithmsList();
        if (!jwsSupportedAlgs.contains(jwsHeader.getAlgorithm().getName())) {
            throw new SynapseException("The " + jwsHeader.getAlgorithm().getName() + " algorithm is not supported");
        }

        // Required and unrecognised claim validation
        validateClaims(jwsHeader);

        // Critical claims validation.
        validateCriticalClaims(jwsHeader, jwksURI);

        // Validate cty claim
        if (!validateCtyClaim(messageContext, jwsHeader)) {
            throw new SynapseException("Error occurred due to invalid cty claim");
        }

        return true;
    }

    /**
     * Content Type (Cty) claim Validation.
     * Content Type (Cty) parameter should be equal to the content type of the request
     *
     * @param messageContext The Synapse MessageContext
     * @param jwsHeader
     */
    private boolean validateCtyClaim(MessageContext messageContext, JWSHeader jwsHeader) {

        String ctyClaim = jwsHeader.getContentType();

        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        Map<String, String> headers = (Map<String, String>)
                axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        String contentType = headers.get(JwsConstants.CONTENT_TYPE_TAG);

        if (ctyClaim != null) {
            if (contentType.contains(JwsConstants.APPLICATION_JSON)) {
                return JwsConstants.APPLICATION_JSON.equals(ctyClaim) || JwsConstants.JSON.equals(ctyClaim);
            } else {
                if (contentType.contains("/") && StringUtils.isNotBlank((contentType.split("/")[1]))) {
                    return (contentType.split("/")[1]).contains(ctyClaim);
                } else {
                    return contentType.equals(ctyClaim);
                }
            }
        }
        return true;
    }

    /**
     * Returns a string list of the supported JWS algorithms.
     *
     * @return List of supported JWS algorithms
     */
    protected List<String> getJwsSupportedAlgorithmsList() {

        return Arrays.stream(jwsSupportedAlgorithms.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    /**
     * Method to Validate each critical claim.
     * This must be a string array consisting of the values for API versions above 3.1.5.
     * "http://openbanking.org.uk/iat", "http://openbanking.org.uk/iss", "http://openbanking.org.uk/tan"
     *
     *
     * @param jwsHeader JOSE Header claims
     * @param jwksURI JwksURL
     */
    protected void validateCriticalClaims(JWSHeader jwsHeader, String jwksURI) {
        /*
         * Validate b64 claim.
         * This must be null for supported versions of UK Toolkit.
         */
        Object b64CustomClaim = jwsHeader.getCustomParam(JwsConstants.B64_CLAIM_KEY);

        if (b64CustomClaim != null) {
            throw new SynapseException("b64 claim must not be present in the header");
        }

        // Validate iat claim.
        validateIatClaim(jwsHeader);

        // Validate iss claim.
        String issClaim = (String) jwsHeader.getCustomParam(JwsConstants.ISS_CLAIM_KEY);

        // Validate if claim is sent.
        if (issClaim == null) {
            throw new SynapseException("Error occurred due to iss claim missing");
        }

        // Check if OpenBanking Directory format. When issued by a TPP, of the form
        // {{orgi-id}}/{{software-statement-id}}
        validateIssClaim(issClaim, jwksURI);

        // Validate if claim is sent.
        String tanClaim = (String) jwsHeader.getCustomParam(JwsConstants.TAN_CLAIM_KEY);
        if (tanClaim == null) {
            throw new SynapseException("Error occurred due to tan claim missing");
        }

        // Trust Anchor Validation.
        validateTanClaim(tanClaim);
    }

    /**
     * Trust Anchor Validation.
     * A string that consists of a domain name that is registered to and identifies the Trust Anchor
     * that hosts the public counter-part of the key used for signing.
     *
     * @param tanClaim
     */
    protected boolean validateTanClaim(String tanClaim) {

        boolean tanValid = false;

        if (StringUtils.isNotEmpty(tanClaim)) {
            tanValid = validTrustAnchor.equals(tanClaim);

            if (!tanValid) {
                throw new SynapseException("Error occurred due to invalid tan claim");
            }
        }
        return true;
    }

    /**
     * Validate iat claim.
     * "The verifier must ensure that the http://openbanking.org.uk/iat claim
     * has a date-time value set in the past."
     *
     * @param jwsHeader
     */
    protected void validateIatClaim(JWSHeader jwsHeader) {

        Object iatCustomClaim = jwsHeader.getCustomParam(JwsConstants.IAT_CLAIM_KEY);
        if (iatCustomClaim == null) {
            throw new SynapseException("Error occurred due to iat claim missing");

            // Check if valid Long -
        } else if (!(iatCustomClaim instanceof Long)) {
            throw new SynapseException("iat claim should be a valid timestamp");
        } else {
            Long iatClaim = (Long) jwsHeader.getCustomParam(JwsConstants.IAT_CLAIM_KEY);

            ZoneId zoneId = ZoneId.of("GMT");

            // Convert timestamp to local date time.
            LocalDateTime iatCreationTime = LocalDateTime.ofInstant(Instant.ofEpochSecond(iatClaim), zoneId);

            // Check iat against current time.
            if (LocalDateTime.now(zoneId).isBefore(iatCreationTime)) {
                throw new SynapseException("iat claim cannot be a future date");
            }
        }
    }

    /**
     * Check if OpenBanking Directory format. The verifier must ensure that PSP bound to the
     * http://openbanking.org.uk/iss claim matches the expected PSP.
     * When issued by a TPP, of the form {{orgi-id}}/{{software-statement-id}}
     *
     * @param issClaim ISS claim to validate
     * @param jwksURI JwksURL to retrieve the public key for verification
     * @return true if the iss claim is valid, false otherwise
     */
    protected boolean validateIssClaim(String issClaim, String jwksURI) {

        boolean isIssValid = true;
        if (StringUtils.isNotEmpty(issClaim)) {
            Pattern obPattern = Pattern.compile(JwsConstants.ISS_FORMAT);
            Matcher issMatcher = obPattern.matcher(issClaim);
            if (issMatcher.matches() && issMatcher.groupCount() == 2) {
                log.debug("Directory specific ISS claim validation applicable");

                // The org_id and software_id has been taken from the JWKS URI.
                if (StringUtils.isNotEmpty(jwksURI)) {
                    //{{org-id}}/{{software-statement-id}}
                    String iss = jwksURI.substring(jwksURI.lastIndexOf("/",
                            jwksURI.lastIndexOf("/") - 1) + 1, jwksURI.lastIndexOf("."));
                    isIssValid = iss.equals(issClaim);
                }
            } else {
                log.debug("SubjectDN ISS claim validation applicable");
                //"CN=jFQuQ4eQbNCMSqdCog21nF, OU=0015800001HQQrZAAX, O=OpenBanking, C=GB".
                // Get RSAKeys required for validation.
                if (StringUtils.isNotEmpty(jwksURI)) {
                    try {
                        X509Certificate x509Certificate = matchingJWK.getParsedX509CertChain().get(0);
                        String subjectDN = x509Certificate.getSubjectDN().getName();
                        //assign subjectDN of the x509Certificate parsed from the matchingJWK.
                        LdapName referenceLDN = new LdapName(subjectDN);
                        //assign subjectDN of the issClaim.
                        LdapName comparingLDN = new LdapName(issClaim);
                        //
                        for (Rdn referenceRdn : referenceLDN.getRdns()) {
                            boolean rdnFound = false;
                            for (Rdn comparingRdn : comparingLDN.getRdns()) {
                                //Loop until the matching Rdn is found to compare.
                                if (referenceRdn.getType().equals(comparingRdn.getType())) {
                                    rdnFound = true;
                                    //compare each Rdn (CN, OU, O) of referenceLDN & comparingLDN.
                                    isIssValid = referenceRdn.getValue().toString()
                                            .equals(comparingRdn.getValue().toString());
                                    break;
                                }
                            }
                            //if current loop has no matching rdn found, return issValid as false.
                            if (!rdnFound)  {
                                isIssValid = false;
                            }

                            if (!isIssValid) {
                                log.error(referenceRdn.getType() + " of the reference Subject DN of does not match " +
                                        "with the comparing Subject DN");
                                break;
                            }
                        }
                    } catch (InvalidNameException e) {
                        log.error("Unable to parse the DN", e);
                        isIssValid = false;
                    }
                }
            }

            if (!isIssValid) {
                throw new SynapseException("Error due to iss claim validation failed");
            }
        }
        return isIssValid;
    }

    /**
     * Method to check the validity of claims sent. In this method it will check whether any unrecognised claims
     * are available or any required claims are missing.
     *
     * @param jwsHeader JWSHeader containing the claims to validate
     */
    protected void validateClaims(JWSHeader jwsHeader) {

        Set<String> criticalParametersSet = jwsHeader.getCriticalParams();
        if (criticalParametersSet == null) {
            throw new SynapseException("Error occurred due to critical parameters claim missing");
        }

        // Critical parameters to sorted array
        Object[] sentClaimObjs = jwsHeader.getCriticalParams().toArray();
        String[] sentClaims = Arrays.copyOf(sentClaimObjs, sentClaimObjs.length, String[].class);
        Arrays.sort(sentClaims);

        // Conversions to get the unrecognised claims
        List<String> sentClaimsList = Arrays.asList(sentClaims);
        List<String> validClaimsList = new ArrayList<>(JwsUtils.getDifferedCritHeaders());

        Set<String> sentClaimsListSet = new HashSet<>(sentClaimsList);
        Set<String> validClaimsListSet = new HashSet<>(validClaimsList);

        // Removing all the known claims to get the unrecognised claims
        sentClaimsListSet.removeAll(validClaimsList);

        if (!sentClaimsListSet.isEmpty()) {
            throw new SynapseException("unrecognised critical parameter");
        }

        // Removing all the unrecognised claims to get the missing known claims
        validClaimsListSet.removeAll(sentClaimsList);

        if (!validClaimsListSet.isEmpty()) {
            throw new SynapseException("required critical parameters missing");
        }
    }

    /**
     * Type claim Validation.
     * Type parameter should be equal to the value "JOSE"
     *
     * @param jwsHeader JWSHeader containing the type claim to validate
     */
    protected boolean validateTypeClaim(JWSHeader jwsHeader) {

        if (jwsHeader.getType() != null) {
            if (jwsHeader.getType().getType() != null) {
                if (!jwsHeader.getType().getType().equals("JOSE")) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Validate whether any unrecognised claims are present.
     *
     * @param jwsHeader JWSHeader containing the claims to validate
     */
    protected void validateAllowedClaims(JWSHeader jwsHeader) {

        List<String> allowedClaims = allowedClaims();
        for (String claim : jwsHeader.getIncludedParams()) {
            if (!allowedClaims.contains(claim)) {
                throw new SynapseException("Error occurred due to an unrecognised claim named , " + claim);
            }
        }
    }

    /**
     * Allowed claims for validation.
     *
     * @return allowed claims
     */
    protected List<String> allowedClaims() {

        String[] claimList = new String[]{JwsConstants.ALG_CLAIM_KEY, JwsConstants.CRIT_CLAIM_KEY,
                JwsConstants.CTY_CLAIM_KEY, JwsConstants.IAT_CLAIM_KEY, JwsConstants.ISS_CLAIM_KEY,
                JwsConstants.KID_CLAIM_KEY, JwsConstants.TYP_CLAIM_KEY, JwsConstants.TAN_CLAIM_KEY};
        Arrays.sort(claimList);

        return Arrays.asList(claimList);
    }

    /**
     * Retrieves the public key from a JWKS endpoint using the provided key ID (kid).
     *
     * @param jwksUrl The URL of the JWKS endpoint
     * @param kid The key ID to look for in the JWKS
     * @return PublicKey corresponding to the provided key ID
     * @throws IOException
     * @throws ParseException
     * @throws JOSEException
     */
    protected PublicKey getPublicKeyFromJWKS(String jwksUrl, String kid)
            throws IOException, ParseException, JOSEException {

        URL jwksEndpoint = new URL(jwksUrl);
        JWKSet jwkSet = JWKSet.load(jwksEndpoint);

        matchingJWK = jwkSet.getKeyByKeyId(kid);

        if (matchingJWK instanceof RSAKey) {
            return ((RSAKey) matchingJWK).toRSAPublicKey();
        } else if (matchingJWK instanceof ECKey) {
            return ((ECKey) matchingJWK).toECPublicKey();
        }

        throw new IllegalArgumentException("Public key with kid=" + kid + " not found in JWKS");
    }

    public String getValidTrustAnchor() {
        return validTrustAnchor;
    }

    public void setValidTrustAnchor(String validTrustAnchor) {
        this.validTrustAnchor = validTrustAnchor;
    }

    public String getJwSignatureHeaderName() {
        return jwSignatureHeaderName;
    }

    public void setJwSignatureHeaderName(String jwSignatureHeaderName) {
        this.jwSignatureHeaderName = jwSignatureHeaderName;
    }

    public String getJwsSupportedAlgorithms() {
        return jwsSupportedAlgorithms;
    }

    public void setJwsSupportedAlgorithms(String jwsSupportedAlgorithms) {
        this.jwsSupportedAlgorithms = jwsSupportedAlgorithms;
    }

    private void setErrorResponseProperties(MessageContext messageContext, String errorCode,
                                                   String errorDescription, String httpStatusCode) {

        messageContext.setProperty(JwsConstants.ERROR_CODE, errorCode);
        messageContext.setProperty(JwsConstants.ERROR_TITLE, "JWS Header Validation Error");
        messageContext.setProperty(JwsConstants.ERROR_DESCRIPTION, errorDescription);
        messageContext.setProperty(JwsConstants.CUSTOM_HTTP_SC, httpStatusCode);
    }

}
