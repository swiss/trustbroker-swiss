/*
 * Copyright (C) 2024 trustbroker.swiss team BIT
 *
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package swiss.trustbroker.saml.util;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.net.URLBuilder;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import swiss.trustbroker.common.exception.ExceptionUtil;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.exception.TrustBrokerException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.Base64Util;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.UrlAcceptor;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.util.QoaMappingUtil;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.util.PropertyUtil;
import swiss.trustbroker.util.WebSupport;

/**
 * Validate (parts of) SAML messages applying our XTB specific business rules to increase security. The XTB security properties
 * allow to control policy checks on a more fine-grained level in case we are too restrictive. The class is used as follows:
 * <ul>
 *   <li>- SAML POST AuthnRequest incoming from RPs - SAML POST Response incoming from CP</li>
 *   <li>- SAML Assertions incoming via WS-Trust 1.3 interface (this one is pre-checked by wss4j with a bad error handling)</li>
 * </ul>
 */
@Slf4j
public class AssertionValidator {

	@Data
	@Builder
	public static class ExpectedAssertionValues {

		private boolean expectSuccess;

		private boolean renew;

		private String expectedRequestId;

		private String expectedIssuer;

		private String expectedAudience;

		private String expectedRpId;

		private String expectedAssertionId;

		private String expectedRelayState;

		private String expectedSessionIndex;

		private String expectedRecipient;

		private QoaComparison expectedCpComparison;

		private List<String> expectedCpContextClasses;

	}

	@Data
	@Builder
	public static class MessageValidationResult {

		private boolean signatureValidated;

		public static MessageValidationResult unvalidated() {
			return MessageValidationResult.builder().build();
		}

	}

	private AssertionValidator() {
	}

	/**
	 * the check 'require signed AuthnRequest' is based on signatureContext (not SecurityPolicies)
	 */
	public static MessageValidationResult validateAuthnRequest(AuthnRequest authnRequest, List<Credential> credentials,
											AcWhitelist acWhiteList, TrustBrokerProperties properties, SecurityPolicies securityPolicies,
											SignatureContext signatureContext, Qoa rpQoa) {
		if (authnRequest == null) {
			throw new RequestDeniedException("Missing authnRequest");
		}

		Instant now = Instant.now();
		log.debug("Start AuthnRequest validation ID={} now={}", authnRequest.getID(), now);

		// service access checks
		validateAssertionConsumer(authnRequest.getAssertionConsumerServiceURL(), acWhiteList, properties, authnRequest);

		// signature first (before we apply any business rules)
		var validationResult = validateRequestSignature(authnRequest, credentials, properties, signatureContext);

		// message checks (stateless)
		validateAuthnRequestId(authnRequest);
		validateAuthnRequestIssuer(authnRequest);
		validateAuthnRequestIssueInstant(authnRequest, now, properties);
		validateAuthnRequestConditions(authnRequest, now, null, false, properties, securityPolicies);

		var issuer = authnRequest.getIssuer() != null ? authnRequest.getIssuer().getValue() : "NONE";
		var qoaConfig = new QoaConfig(rpQoa, issuer);
		var authnRequestContextClasses = OpenSamlUtil.extractAuthnRequestContextClasses(authnRequest, qoaConfig.isReplaceInbound(),
				QoaMappingUtil.getReplacementAcClasses(rpQoa));
		var requestComparison = OpenSamlUtil.extractAuthnRequestComparison(authnRequest);
		boolean enforceQoaIfMissing = properties.getSecurity().isEnforceQoaIfMissing();
		validateAuthnContextClassRefs(qoaConfig, authnRequestContextClasses, requestComparison, properties.getQoaMap(), enforceQoaIfMissing);

		// Audit facility does INFO logging
		log.debug("AuthnRequest validation was successful for requestID={} validationResult={}",
				authnRequest.getID(), validationResult);
		return validationResult;
	}

	static void validateAuthnContextClassRefs(QoaConfig qoaConfig, List<String> requestContextClasses,
													  AuthnContextComparisonTypeEnumeration comparison, Map<String, Integer> qoaMap,
													  boolean enforceQoaIfMissing) {
		if (requestContextClasses.isEmpty()) {
			var issuerId = qoaConfig.issuerId();
			QoaMappingUtil.rejectRequestIfQoaConfMissing(qoaConfig.hasConfig() ? qoaConfig.config() : null, enforceQoaIfMissing, issuerId);
			log.debug("Missing AuthnRequest contextClasses from request with ID={}", issuerId);
			return;
		}

		QoaMappingUtil.validateRpContextClasses(qoaConfig, requestContextClasses, comparison, qoaMap);
	}

	/**
	 * @return signatureValidated true if for the response and all assertions, a signature is present and has been successfully
	 * validated
 	 */
	public static MessageValidationResult validateResponse(ResponseData<Response> responseData, List<Assertion> assertions,
			List<Credential> credentials, TrustBrokerProperties properties, ClaimsParty claimsParty,
			Qoa qoa, ExpectedAssertionValues expectedValues) {
		if (responseData == null || responseData.getResponse() == null) {
			throw new RequestDeniedException("Missing response");
		}
		var response = responseData.getResponse();

		Instant now = Instant.now();
		log.debug("Start Response validation ID={} inResponseTo={} now={}", response.getID(), response.getInResponseTo(), now);

		// signature first (before we apply any business rules)
		var requireSignedResponse = requireSignedResponse(properties, claimsParty.getSecurityPolicies());
		// response only, not assertion
		var validationResult = validateResponseSignature(response, credentials, requireSignedResponse);

		// message checks (stateless)
		// also check that status is not SUCCESS if failure is expected, else we would sign unvalidated assertions
		validateResponseStatus(expectedValues.expectSuccess, response);
		validateResponseId(response);
		validateResponseIssueInstant(response, now, properties);

		// session dependent checks (stateful)
		validateRelayState(expectedValues.expectedRelayState, responseData.getRelayState(), properties, response);
		validateResponseIssuer(response, expectedValues.expectedIssuer, properties);
		if (expectedValues.expectSuccess) {
			if (expectedValues.expectedRequestId == null) {
				expectedValues.setExpectedRequestId(response.getInResponseTo());
			}
			var assertionValidationResult =
					validateResponseAssertions(assertions, response, credentials, properties, claimsParty, qoa, expectedValues);
			validationResult.signatureValidated &= assertionValidationResult.signatureValidated;
		}
		// else: no assertions

		// Audit facility does INFO logging
		log.debug("Response validation was successful for ID={} inResponseTo={} validationResult={}",
				response.getID(), response.getInResponseTo(), validationResult);
		return validationResult;
	}

	// returns signatureValidated true if for all assertions a signature is present and has been successfully validated
	static MessageValidationResult validateResponseAssertions(List<Assertion> assertions, Response response, List<Credential> credentials,
			TrustBrokerProperties properties, ClaimsParty claimsParty, Qoa qoa, ExpectedAssertionValues expectedValues) {

		if (assertions == null || assertions.isEmpty()) {
			throw new RequestDeniedException(
					String.format("Response doesn't contain assertions: %s", OpenSamlUtil.samlObjectToString(response)));
		}
		if (assertions.size() != 1 && log.isWarnEnabled()) {
			log.warn("Response contains more than 1 assertion: {}", OpenSamlUtil.samlObjectToString(response));
		}
		return validateAssertions(assertions, credentials, properties, claimsParty, qoa, response, expectedValues);
	}

	// returns signatureValidated true if for all assertions a signature is present and has been successfully validated
	static MessageValidationResult validateAssertions(List<Assertion> assertions, List<Credential> credentials,
			TrustBrokerProperties properties, ClaimsParty claimsParty, Qoa qoa, XMLObject xmlObject,
			ExpectedAssertionValues expectedValues) {
		if (assertions == null || assertions.isEmpty() || assertions.get(0) == null) {
			throw new RequestDeniedException(String.format(
					"Assertions missing: %s",
					OpenSamlUtil.samlObjectToString(xmlObject)));
		}
		Instant now = Instant.now();
		var assertionsValidated = MessageValidationResult.builder()
														 .signatureValidated(true)
														 .build();
		for (Assertion assertion : assertions) {
			var assertionValidated = validateAssertion(assertion, now, credentials, properties, claimsParty, qoa, expectedValues);
			assertionsValidated.signatureValidated &= assertionValidated.signatureValidated;
		}
		return assertionsValidated;
	}

	/**
	 * RST case of WSTrust service: The header assertion is already checked by <code>wss4j</code>.
	 * @param assertion
	 * @param properties
	 * @param claimsParty
	 * @param securityPolicies
	 * @param now current time if null
	 * @param expectedValues default ExpectedAssertionValues if null
	 * @param signatureValidationCredentials signature checked if present
	 * @return validation result
	 */
	public static MessageValidationResult validateRstAssertion(Assertion assertion, TrustBrokerProperties properties,
			ClaimsParty claimsParty, SecurityPolicies securityPolicies, Instant now, ExpectedAssertionValues expectedValues,
			Optional<List<Credential>> signatureValidationCredentials) {
		if (assertion == null) {
			throw new RequestDeniedException("Assertion missing");
		}
		if (expectedValues == null) {
			expectedValues = ExpectedAssertionValues.builder().build();
		}

		if (now == null) {
			now = Instant.now();
		}
		log.debug("Start Assertion validation ID={} now={} excluding signature check (wss4j case)", assertion.getID(), now);

		// message checks (stateless)
		var validationResult = MessageValidationResult.unvalidated();
		if (signatureValidationCredentials.isPresent()) {
			validationResult = validateAssertionSignature(assertion, signatureValidationCredentials.get(), properties);
		}
		validateAssertionId(assertion);
		validateAssertionIssueInstant(assertion, now, expectedValues.renew, properties, securityPolicies);
		validateAssertionIssuer(assertion, expectedValues.expectedIssuer, properties);
		validateAssertionSubject(assertion, now, expectedValues.expectedRequestId, true,
				expectedValues.renew, expectedValues.expectedRecipient, properties);
		validateAssertionConditions(assertion, now, expectedValues.expectedAudience, expectedValues.renew,
				properties, securityPolicies);
		validateAssertionAuthnStatements(assertion, now, claimsParty, new QoaConfig(null, null), properties,
				expectedValues.expectedCpContextClasses, null, expectedValues.renew);
		validateAssertionAttributeStatements(assertion);

		log.debug("RST assertion validation was successful for ID={} validationResult={}",
				assertion.getID(), validationResult);
		return validationResult;
	}

	public static MessageValidationResult validateAssertion(Assertion assertion, Instant now, List<Credential> credentials,
			TrustBrokerProperties properties, ClaimsParty claimsParty, Qoa qoa, ExpectedAssertionValues expectedValues) {
		var securityPolicies = claimsParty != null ? claimsParty.getSecurityPolicies(): null;
		if (assertion == null) {
			throw new RequestDeniedException("Assertion missing");
		}

		log.debug("Start Assertion validation ID={} now={} including signature check", assertion.getID(), now);

		// signature first (before we apply any business rules)
		var validationResult = validateAssertionSignature(assertion, credentials, properties);

		// message checks (stateless)
		validateAssertionId(assertion);
		validateAssertionIssueInstant(assertion, now, expectedValues.renew, properties, securityPolicies);
		validateAssertionIssuer(assertion, expectedValues.expectedIssuer, properties);
		validateAssertionSubject(assertion, now, expectedValues.expectedAssertionId, false,
				expectedValues.renew, expectedValues.expectedRecipient, properties);
		validateAssertionConditions(assertion, now, expectedValues.expectedAudience, expectedValues.renew,
				properties, securityPolicies);
		var qoaConfig = new QoaConfig(qoa, expectedValues.getExpectedRpId());
		validateAssertionAuthnStatements(assertion, now, claimsParty, qoaConfig, properties,
				expectedValues.getExpectedCpContextClasses(), expectedValues.getExpectedCpComparison(), expectedValues.renew);
		validateAssertionAttributeStatements(assertion);

		log.debug("Assertion validation was successful for ID={} validationResult={}", assertion.getID(), validationResult);
		return validationResult;
	}

	// As SAML message validation is stateful, we accept session checks in here (for now)
	static void validateRpSession(StateData state) {
		if (state == null || !state.isValid()) {
			// we leak sensitive information here so just leak the session ID and check what we report in Audit.audit
			throw new RequestDeniedException(String.format("Invalid sessionId='%s'", state == null ? state : state.getId()));
		}
	}

	public static void validCpSession(StateData state) {
		validateRpSession(state);
		if (state.getSpStateData() == null || !state.getSpStateData().isValid()) {
			throw new RequestDeniedException(String.format(
					"Invalid CP session with no RP state cpSessionId='%s', rpSessionId='%s'",
					state.getId(), state.getSpStateData() == null ? null : state.getSpStateData().getId()));
		}
	}

	static void validateAuthnRequestId(AuthnRequest authnRequest) {
		if (authnRequest == null || StringUtils.isBlank(authnRequest.getID())) {
			throw new RequestDeniedException(String.format(
					"AuthnRequest.ID missing: %s", OpenSamlUtil.samlObjectToString(authnRequest)));
		}
	}

	static void validateResponseId(Response response) {
		if (StringUtils.isBlank(response.getID())) {
			throw new RequestDeniedException(String.format(
					"Response.ID missing: %s", OpenSamlUtil.samlObjectToString(response)));
		}
		if (StringUtils.isBlank(response.getInResponseTo())) {
			throw new RequestDeniedException(String.format(
					"Response.InResponseTo missing: %s", OpenSamlUtil.samlObjectToString(response)));
		}
	}

	static void validateAssertionId(Assertion assertion) {
		if (StringUtils.isBlank(assertion.getID())) {
			throw new RequestDeniedException(String.format(
					"Assertion.ID missing: %s", OpenSamlUtil.samlObjectToString(assertion)));
		}
	}

	static void validateAuthnRequestIssuer(AuthnRequest authnRequest) {
		if (authnRequest.getIssuer() == null || StringUtils.isBlank(authnRequest.getIssuer().getValue())) {
			throw new RequestDeniedException(String.format(
					"Issuer missing: %s", OpenSamlUtil.samlObjectToString(authnRequest)));
		}
	}

	static void validateResponseIssuer(Response response, String expectedIssuer, TrustBrokerProperties properties) {
		if (response.getIssuer() == null || response.getIssuer().getValue() == null) {
			// we expect an issuer to always be present (state or not, SAML POST or WSTrust
			throw new RequestDeniedException(String.format(
					"Response.Issuer missing: %s", OpenSamlUtil.samlObjectToString(response)));
		}
		// validating a response always requires or AuthnRequest or SSO related state
		String actualIssuer = response.getIssuer().getValue();
		if (!actualIssuer.equals(expectedIssuer)) {
			if (properties.getSecurity().isValidateResponseIssuer()) {
				throw new RequestDeniedException(String.format(
						"Response.Issuer invalid actualIssuer='%s' expectedIssuer='%s': %s",
						actualIssuer, expectedIssuer, OpenSamlUtil.samlObjectToString(response)));
			}
			// in discontinued stealth mode this would pop up in PROD, se reduce log level, signature is checked anyway first
			log.debug("trustbroker.config.security.validateResponseIssuer=false: CP-IdP issuer not checked!!!");
		}
	}

	static void validateAssertionIssuer(Assertion assertion, String expectedIssuer, TrustBrokerProperties properties) {
		var issuer = assertion.getIssuer();
		if (issuer == null || StringUtils.isBlank(issuer.getValue())) {
			throw new RequestDeniedException(String.format(
					"Assertion.Issuer missing: %s", OpenSamlUtil.samlObjectToString(assertion)));
		}
		if (expectedIssuer != null && !expectedIssuer.equals(issuer.getValue())) {
			if (properties.getSecurity().isValidateResponseIssuer()) {
				throw new RequestDeniedException(String.format(
						"Assertion.Issuer='%s' is different from the expected Issuer='%s' in: %s",
						issuer.getValue(), expectedIssuer, OpenSamlUtil.samlObjectToString(assertion)));
			}
			// in discontinued stealth mode, we do not know the selected IDP un AuthnRequest, so we cannot assert
			log.debug("Assertion.Issuer='{}' is different from the expected Issuer='{}'",
					issuer.getValue(), expectedIssuer);
		}
	}

	public static MessageValidationResult validateRequestSignature(RequestAbstractType request, List<Credential> credentials,
			TrustBrokerProperties properties, SignatureContext signatureContext) {
		var signed = request.isSigned();
		log.debug("{} id={} signed={}", request.getClass().getName(), request.getID(), signed);
		if (!signed && (signatureContext.getBinding() == SamlBinding.REDIRECT)) {
			// we parse the URL twice this way, but this is cheap
			signed = isRedirectMessageSigned(signatureContext);
			log.debug("Redirect binding with unsigned {} id={}, query signed={}",
					request.getClass().getName(), request.getID(), signed);
		}
		if (!signed) {
			if (!properties.getSecurity().isRequireSignedAuthnRequest()) {
				log.debug("trustbroker.config.security.requireSignedAuthnRequest=false: Accepted unsigned {}!!!",
						request.getClass().getName());
				return MessageValidationResult.unvalidated();
			}
			if (!signatureContext.isRequireSignature()) {
				log.debug("RP SecurityPolicies.requireSignedAuthnRequest=false: Accepted unsigned {}!!!",
						request.getClass().getName());
				return MessageValidationResult.unvalidated();
			}
			else {
				throw new RequestDeniedException(String.format(
						"%s not signed and requireSignedAuthnRequest=true: %s",
						request.getClass().getName(), OpenSamlUtil.samlObjectToString(request)));
			}
		}
		return validateSignature(request.getSignature(), credentials, request, signatureContext);
	}

	static MessageValidationResult validateResponseSignature(Response response, List<Credential> credentials, boolean requireSignedResponse) {
		if (!response.isSigned()) {
			if (requireSignedResponse) {
				throw new RequestDeniedException(String.format(
						"Response not signed: %s", OpenSamlUtil.samlObjectToString(response)));
			}
			log.debug("trustbroker.config.security.requireSignedResponse=false: Accepted unsigned response, rely on Assertion.");
			return MessageValidationResult.unvalidated();
		}
		var signatureContext = SignatureContext.forPostBinding();
		signatureContext.setRequireSignature(requireSignedResponse);
		return validateSignature(response.getSignature(), credentials, response, signatureContext);
	}

	static MessageValidationResult validateAssertionSignature(Assertion assertion,
			List<Credential> credentials, TrustBrokerProperties properties) {
		if (!assertion.isSigned()) {
			if (properties.getSecurity().isRequireSignedAssertion()) {
				throw new RequestDeniedException(String.format(
						"Assertion not signed: %s", OpenSamlUtil.samlObjectToString(assertion)));
			}
			if (log.isErrorEnabled()) {
				log.error("trustbroker.config.security.requireSignedAssertion=false: Accepted unsigned Assertion: {}",
						OpenSamlUtil.samlObjectToString(assertion));
			}
			return MessageValidationResult.unvalidated();
		}
		var signatureContext = SignatureContext.forPostBinding();
		signatureContext.setRequireSignature(properties.getSecurity().isRequireSignedAssertion());
		return validateSignature(assertion.getSignature(), credentials, assertion, signatureContext);
	}

	static void validateRedirectBindingSignature(SignatureContext signatureContext,
			List<Credential> credentials) {
		if (signatureContext.getBinding() != SamlBinding.REDIRECT) {
			throw new TechnicalException(
					String.format("Called with invalid context for binding %s", signatureContext.getBinding()));
		}
		var urlBuilder = urlBuilderForRedirectBinding(signatureContext);
		var samlMessageName = SamlIoUtil.SAML_REQUEST_NAME;
		var samlMessage = WebSupport.getUniqueQueryParameter(urlBuilder, samlMessageName);
		if (samlMessage == null) {
			samlMessageName = SamlIoUtil.SAML_RESPONSE_NAME;
			samlMessage = WebSupport.getUniqueQueryParameter(urlBuilder, samlMessageName);
		}
		// we should not get here without a message
		if (samlMessage == null) {
			throw new RequestDeniedException(String.format("Missing message in URL: %s", signatureContext.getRequestUrl()));
		}

		var signature = WebSupport.getUniqueQueryParameter(urlBuilder, SamlIoUtil.SAML_REDIRECT_SIGNATURE);
		var signatureAlgorithm = WebSupport.getUniqueQueryParameter(urlBuilder, SamlIoUtil.SAML_REDIRECT_SIGNATURE_ALGORITHM);
		if (signature == null || signatureAlgorithm == null) {
			throw new RequestDeniedException(String.format("%s or %s missing in URL: %s",
					SamlIoUtil.SAML_REDIRECT_SIGNATURE, SamlIoUtil.SAML_REDIRECT_SIGNATURE_ALGORITHM,
					StringUtil.clean(signatureContext.getRequestUrl())));
		}

		// relayState required according to spec when provided
		var relayState = WebSupport.getUniqueQueryParameter(urlBuilder, SamlIoUtil.SAML_RELAY_STATE);
		var queryParams = urlBuilder.getQueryParams();
		queryParams.clear();
		queryParams.add(new Pair<>(samlMessageName, samlMessage));
		if (StringUtils.isNotEmpty(relayState)) {
			queryParams.add(new Pair<>(SamlIoUtil.SAML_RELAY_STATE, relayState));
		}
		queryParams.add(new Pair<>(SamlIoUtil.SAML_REDIRECT_SIGNATURE_ALGORITHM, signatureAlgorithm));
		var queryString = urlBuilder.buildQueryString();
		var signatureBytes = Base64Util.decode(signature);

		// signature check (optional if not required by config)
		boolean signatureValid = SamlUtil.isRedirectSignatureValid(credentials, signatureAlgorithm, queryString,
				signatureBytes);
		if (!signatureValid) {
			throw new RequestDeniedException(String.format("%s or %s invalid in URL: %s",
					SamlIoUtil.SAML_REDIRECT_SIGNATURE, SamlIoUtil.SAML_REDIRECT_SIGNATURE_ALGORITHM,
					StringUtil.clean(signatureContext.getRequestUrl())));
		}

		log.debug("Accepted valid SAML redirect message on: {}", signatureContext.getRequestUrl());
	}

	private static URLBuilder urlBuilderForRedirectBinding(SignatureContext signatureContext) {
		try {
			// URLBuilder expects a full URL, we only care about the query params here
			var url = "https://localhost" + signatureContext.getRequestUrl();
			return new URLBuilder(url);
		}
		catch (final MalformedURLException e) {
			// an invalid URL could be an attack (or a bug)
			throw new RequestDeniedException(String.format("URL %s is not a valid URL",
					StringUtil.clean(signatureContext.getRequestUrl())), e);
		}
	}

	private static boolean isRedirectMessageSigned(SignatureContext signatureContext) {
		var urlBuilder = urlBuilderForRedirectBinding(signatureContext);
		var signature = WebSupport.getUniqueQueryParameter(urlBuilder, SamlIoUtil.SAML_REDIRECT_SIGNATURE);
		var signatureAlgorithm = WebSupport.getUniqueQueryParameter(urlBuilder, SamlIoUtil.SAML_REDIRECT_SIGNATURE_ALGORITHM);
		return signature != null && signatureAlgorithm != null;
	}

	static MessageValidationResult validateSignature(Signature signature, List<Credential> credentials, XMLObject xmlObject,
			SignatureContext signatureContext) {
		try {
			// accept SAML message because we do not have a credential
			if (CollectionUtils.isEmpty(credentials)) {
				throw new RequestDeniedException(String.format(
						"Signer truststore missing: %s", OpenSamlUtil.samlObjectToString(xmlObject)));
			}

			// REDIRECT binding: Handle it with the separated signature parameters in the URL
			if (signatureContext.getBinding() == SamlBinding.REDIRECT && signature == null) {
				validateRedirectBindingSignature(signatureContext, credentials);
			}

			// POST or ARTIFACT binding or when REDIRECT binding SAMLRequest/Response is signed itself
			else  {
				validateSamlPostBindingSignature(signature, credentials, xmlObject);
			}
			return MessageValidationResult.builder().signatureValidated(true).build();
		}
		catch (TrustBrokerException ex) {
			if (signatureContext.isRequireSignature()) {
				throw ex;
			}
			if (xmlObject instanceof Response || xmlObject instanceof Assertion) {
				log.error("Signature verification failed for {} (signature check disabled in config): {}",
						xmlObject.getClass().getSimpleName(), ex.getInternalMessage());
			}
			else {
				log.info("Signature verification failed for {}, but not required in config: {}",
						xmlObject.getClass().getSimpleName(), ex.getInternalMessage());
			}
			return MessageValidationResult.unvalidated();
		}
	}

	private static void validateSamlPostBindingSignature(Signature signature, List<Credential> credentials,
			XMLObject xmlObject) {
		var profileValidator = new SAMLSignatureProfileValidator();
		try {
			profileValidator.validate(signature);
		}
		catch (SignatureException e) {
			throw new RequestDeniedException(String.format("Signature profile validation failed with '%s': %s",
					ExceptionUtil.getRootMessage(e), OpenSamlUtil.samlObjectToString(xmlObject)), e);
		}

		if (!SamlUtil.isSignatureValid(signature, credentials)) {
			throw new RequestDeniedException(String.format(
					"SAML Signature validation failed using signer='%s' using configured verifiers='%s'. Message details: %s",
					SamlUtil.getKeyInfoHintFromSignature(signature),
					SamlUtil.credentialsToKeyInfo(credentials),
					OpenSamlUtil.samlObjectToString(xmlObject)));
		}
		if (log.isDebugEnabled()) {
			log.debug("Accepted valid SAML POST message: {}", OpenSamlUtil.samlObjectToString(xmlObject));
		}
	}

	static void validateAuthnRequestIssueInstant(AuthnRequest authnRequest, Instant nowOffsetDateTime,
			TrustBrokerProperties properties) {
		if (properties.getSecurity().isValidateRequestIssueInstant()) {
			validateTimestampInRange("AuthnRequest.IssueInstant",
					authnRequest.getIssueInstant(), nowOffsetDateTime,
					properties.getSecurity().getNotBeforeToleranceSec(),
					properties.getSecurity().getMessageLifetimeSec(),
					authnRequest);
		}
		else {
			// DEBUG: SAML AuthnRequest are short-lived but SAML2 spec does not really define enforcement, we therefore just debug
			log.debug("Response.IssueInstant validation disabled globally using " +
					"trustbroker.config.security.validateRequestIssueInstant");
		}
	}

	static void validateAssertionAttributeStatements(Assertion assertion) {
		// Attributes optional but a bit fishy
		List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
		if (CollectionUtils.isEmpty(attributeStatements) && log.isInfoEnabled()) {
			log.info("AttributeStatements missing: {}", OpenSamlUtil.samlObjectToString(assertion));
		}
	}

	static void validateAssertionAuthnStatements(Assertion assertion, Instant nowOffsetDateTime, ClaimsParty claimsParty,
												 QoaConfig rpQoaConf, TrustBrokerProperties properties,
												 List<String> expectedContextClasses, QoaComparison comparison, boolean renew) {

		var authnStatements = assertion.getAuthnStatements();
		var cpQoaConf =  claimsParty != null ? claimsParty.getQoaConfig() : new QoaConfig(null, null);

		if (CollectionUtils.isEmpty(authnStatements)) {
			QoaMappingUtil.missingQoaException(comparison, expectedContextClasses, cpQoaConf, rpQoaConf);
			return;
		}

		var securityPolicies = claimsParty != null ? claimsParty.getSecurityPolicies(): null;
		Map<String, Integer> globalMapping = properties.getQoaMap();

		// should be just one element in the list
		for (AuthnStatement authnStatement : authnStatements) {
			if (properties.getSecurity().isValidateAuthnStatementIssueInstant()) {
				validateTimestampInRange("AuthnStatement.AuthnInstant",
						authnStatement.getAuthnInstant(), nowOffsetDateTime,
						properties.getSecurity().getNotBeforeToleranceSec(),
						getNotOnOrAfterSeconds(properties, securityPolicies, renew),
						assertion);
			}

			// Validate with CP Qoa requirement
			var assertionContextClass = OpenSamlUtil.extractAuthnStatementContextClass(authnStatement);
			validateQoaRequirement(assertionContextClass, cpQoaConf, comparison, expectedContextClasses, globalMapping, rpQoaConf.issuerId());
		}
	}

	public static void validateQoaRequirement(String contextClass, QoaConfig qoaConfig, QoaComparison comparison,
											  List<String> expectedContextClasses,
											  Map<String, Integer> globalMapping, String issuer) {
		QoaMappingUtil.validateContextClass(
				comparison, expectedContextClasses, qoaConfig,
				contextClass, qoaConfig,
				issuer, globalMapping, false);
	}

	private static Long getNotOnOrAfterSeconds(TrustBrokerProperties properties, SecurityPolicies securityPolicies, boolean renew) {
		var result = PropertyUtil.evaluatePositiveNumberProperty(
				securityPolicies, SecurityPolicies::getNotOnOrAfterSeconds,
				() -> properties.getSecurity().getTokenLifetimeSec() // not null
		).longValue();
		if (renew) {
			// RENEW allows expired assertions to be used after this tolerance - for issue times this is added to the lifetime
			result += properties.getSecurity().getRenewNotOnOrAfterToleranceRenewSec();
		}
		return result;
	}

	private static long getNotOnOrAfterToleranceSec(boolean renew, TrustBrokerProperties properties) {
		return renew ? properties.getSecurity().getRenewNotOnOrAfterToleranceRenewSec() :
				properties.getSecurity().getNotOnOrAfterToleranceSec();
	}

	private static String extractIssuer(XMLObject xmlObject) {
		Issuer issuer = null;
		if (xmlObject instanceof StatusResponseType response) {
			issuer = response.getIssuer();
		}
		else if (xmlObject instanceof RequestAbstractType request) {
			issuer = request.getIssuer();
		}
		else if (xmlObject instanceof Assertion assertion) {
			issuer = assertion.getIssuer();
		}
		return issuer == null ? "missing" : issuer.getValue();
	}

	static void validateTimestampInRange(String elementName, Instant messageDateTime, Instant nowOffsetDateTime,
			long notBeforeToleranceSec, long notOnOrAfterToleranceSec, XMLObject xmlObject) {
		if (messageDateTime != null) {
			var notBeforeTolerance = Duration.ofSeconds(notBeforeToleranceSec);
			var notOnOrAfterTolerance = Duration.ofSeconds(notOnOrAfterToleranceSec);
			var duration = Duration.between(messageDateTime, nowOffsetDateTime);
			var issuer = extractIssuer(xmlObject);
			if (duration.compareTo(notOnOrAfterTolerance) > 0 || duration.compareTo(notBeforeTolerance) < 0) {
				throw new RequestDeniedException(String.format(
						"%s=%s not valid now=%s for issuer=%s with diffSec=%s " +
								"considering notBeforeToleranceSec=%s notOnOrAfterToleranceSec=%s " +
								"acceptedRange=[%s..%s]. Message: %s",
						elementName, messageDateTime, nowOffsetDateTime, issuer, duration.getSeconds(),
						notBeforeToleranceSec, notOnOrAfterToleranceSec,
						notBeforeTolerance, notOnOrAfterTolerance,
						OpenSamlUtil.samlObjectToString(xmlObject)));
			}
			else if (duration.isNegative()) {
				if (log.isWarnEnabled()) {
					log.warn("{}={} drifting as of now now={} for issuer={} with diffSec={} within acceptedRange=[{}..{}]." +
									" HINT: Check NTP drift of peer and this host. Message: {}",
							elementName, messageDateTime, nowOffsetDateTime, issuer, duration.getSeconds(),
							notBeforeTolerance, notOnOrAfterTolerance,
							OpenSamlUtil.samlObjectToString(xmlObject));
				}
			}
			else {
				if (log.isDebugEnabled()) {
					log.debug("{}={} in range as of now={} for issuer={} with diffSec={} " +
									"within acceptedRange=[{}..{}]. Message: {}",
							elementName, messageDateTime, nowOffsetDateTime, issuer, duration.getSeconds(),
							notBeforeTolerance, notOnOrAfterTolerance,
							OpenSamlUtil.samlObjectToString(xmlObject));
				}
			}
		}
		else if (log.isWarnEnabled()) {
			log.error("{} missing: {}", elementName, OpenSamlUtil.samlObjectToString(xmlObject));
		}
	}

	static void validateAuthnRequestConditions(AuthnRequest authnRequest, Instant now, String expectedAudience, boolean renew,
			TrustBrokerProperties properties, SecurityPolicies securityPolicies) {
		if (properties.getSecurity().isValidateRequestCondition()) {
			validateConditions(authnRequest.getConditions(), now, expectedAudience, renew, properties, securityPolicies, authnRequest);
		}
		else {
			log.warn("AuthnRequest.Conditions validation disabled");
		}

	}

	static void validateAssertionConditions(Assertion assertion, Instant now, String expectedAudience, boolean renew,
			TrustBrokerProperties properties, SecurityPolicies securityPolicies) {
		validateConditions(assertion.getConditions(), now, expectedAudience, renew, properties, securityPolicies, assertion);
	}

	static void validateConditions(Conditions conditions, Instant now, String expectedAudience, boolean renew,
			TrustBrokerProperties properties, SecurityPolicies securityPolicies, XMLObject xmlObject) {
		// conditions are optional as long as we do mot have any MUST policies
		if (conditions == null) {
			if (log.isDebugEnabled()) {
				log.debug("No Conditions, nothing to check: {}", OpenSamlUtil.samlObjectToString(xmlObject));
			}
			return;
		}

		// time checks
		Instant notBefore = conditions.getNotBefore();
		Instant notOnOrAfter = conditions.getNotOnOrAfter();
		validateNotBeforeAndNotAfter("Condition",
				notBefore, notOnOrAfter, now,
				properties.getSecurity().getNotBeforeToleranceSec(),
				getNotOnOrAfterToleranceSec(renew, properties),
				xmlObject);

		// audience
		validateAudienceRestrictions(conditions.getAudienceRestrictions(), expectedAudience, properties,
				securityPolicies, xmlObject);
	}

	// Conditions optional but an AudienceRestriction shall have an Audience matching the issuer ID of the provider
	// https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf Page 24, Line 976
	// The Audience URI MAY identify a document that describes the terms and conditions of audience membership.
	// It MAY contain the unique identifier URI from a SAML name identifier that describes a system entity.
	// HINT: This means, that with an audience we restrict usage of the token to exactly that issuer ID.
	static void validateAudienceRestrictions(List<AudienceRestriction> audienceRestrictions, String expectedAudience,
			TrustBrokerProperties properties, SecurityPolicies securityPolicies, XMLObject xmlObject) {
		// bailout when we are too restrictive and have disabled the check
		if (!properties.getSecurity().isValidateAudience()) {
			log.info("trustbroker.config.security.validateAudience=false: Audience restrictions not checked!!!");
			return;
		}

		// we accept only ourselves as issuer currently, and an optional input
		Set<String> acceptedAudiences = new HashSet<>();
		if (StringUtils.isNotEmpty(expectedAudience)) {
			acceptedAudiences.add(expectedAudience);
		}
		// accept our own AC URL too
		var issuerAclUrl = properties.getSamlConsumerUrl();
		if (StringUtils.isNotEmpty(issuerAclUrl)) {
			acceptedAudiences.add(issuerAclUrl);
		}
		var svcIssuer = properties.getIssuer();
		if (StringUtils.isNotEmpty(svcIssuer)) {
			acceptedAudiences.add(svcIssuer);
		}
		// svcIssuer is only required without expectedAudience
		else if (acceptedAudiences.isEmpty()) {
			throw new RequestDeniedException("Issuer missing in service configuration");
		}

		var debugAudiences = CollectionUtil.toLogString(acceptedAudiences);

		// check any
		int acceptedAudiencesCount = acceptedAudiences.size();
		var foundAudiencesCount = 0;
		List<String> messageAudiences = new ArrayList<>();
		for (AudienceRestriction restriction : audienceRestrictions) {
			for (Audience audience : restriction.getAudiences()) {
				foundAudiencesCount++;
				String audienceUri = audience.getURI();
				messageAudiences.add(audienceUri);
				log.debug("Checking received audience '{}' against accepted audiences {}", audienceUri, debugAudiences);
				acceptedAudiences.remove(audienceUri);
			}
		}
		// nothing removed so we did not have any match
		boolean noAudienceMatched = acceptedAudiences.size() == acceptedAudiencesCount;
		boolean audienceRequired = requireAudienceRestriction(properties, securityPolicies);
		if (noAudienceMatched && (foundAudiencesCount > 0 || audienceRequired)) {
			throw new RequestDeniedException(String.format(
					"Audience missing or invalid, received='%s', accepted='%s': %s",
					CollectionUtil.toLogString(messageAudiences), debugAudiences, OpenSamlUtil.samlObjectToString(xmlObject)));
		}
	}

	static boolean requireAudienceRestriction(TrustBrokerProperties properties, SecurityPolicies securityPolicies) {
		return PropertyUtil.evaluatePropery(securityPolicies,
				SecurityPolicies::getRequireAudienceRestriction,
				() -> properties.getSecurity().isRequireAudienceRestriction());
	}

	static boolean requireSignedResponse(TrustBrokerProperties properties, SecurityPolicies securityPolicies) {
		return PropertyUtil.evaluatePropery(securityPolicies,
				SecurityPolicies::getRequireSignedResponse,
				() -> properties.getSecurity().isRequireSignedResponse());
	}

	static void validateNotBeforeAndNotAfter(String elementName, Instant notBefore, Instant notOnOrAfter,
			Instant now, long notBeforeToleranceSec, long notOnOrAfterToleranceSec, XMLObject xmlObject) {
		// SubjectConfirmationData.NotBefore and Condition.NotBefore handled the same way as IssueInstant
		// except that we do not check the range tolerance in the future.
		if (notBefore != null) {
			validateTimestampInRange(elementName + ".NotBefore", notBefore, now,
					notBeforeToleranceSec, Long.MAX_VALUE,
					xmlObject);
		}
		if (notOnOrAfter != null) {
			// incoming timestamp before now - 480s per default
			var nowWithTolerance = now.minusSeconds(notOnOrAfterToleranceSec - 1);
			if (nowWithTolerance.isAfter(notOnOrAfter)) {
				var issuer = extractIssuer(xmlObject);
				var duration = Duration.between(notOnOrAfter, now);
				throw new RequestDeniedException(String.format(
						"%s.NotOnOrAfter='%s' not valid now='%s' for issuer=%s with diffSec=%s " +
								"considering notOnOrAfterToleranceSec=%s. Message: %s",
						elementName, notOnOrAfter, now, issuer, duration.getSeconds(), notOnOrAfterToleranceSec,
						OpenSamlUtil.samlObjectToString(xmlObject)));
			}
		}
	}

	static void validateResponseStatus(boolean expectSuccess, Response response) {
		String statusCode = OpenSamlUtil.getStatusCode(response);
		String statusMessage = OpenSamlUtil.getStatusMessage(response);
		if (expectSuccess) {
			if (!StatusCode.SUCCESS.equals(statusCode)) {
				throw new RequestDeniedException(String.format(
						"Invalid statusCode='%s/%s' in: %s",
						statusCode, statusMessage, OpenSamlUtil.samlObjectToString(response)));
			}
		}
		else {
			if (StatusCode.SUCCESS.equals(statusCode)) {
				throw new RequestDeniedException(String.format(
						"Invalid SUCCESS statusCode='%s/%s' in: %s",
						statusCode, statusMessage, OpenSamlUtil.samlObjectToString(response)));
			}

		}
	}

	static void validateRelayState(String existingRelayState, String incomingRelayState,
			TrustBrokerProperties properties, XMLObject xmlObject) {
		if (!properties.getSecurity().isValidateRelayState()) {
			log.info("trustbroker.config.security.validateRelayState=false: RelaySate ignored!!!");
			return;
		}
		if (existingRelayState == null || incomingRelayState == null) {
			throw new RequestDeniedException(String.format(
					"RelayState missing incoming='%s' existing='%s', blocking: %s",
					incomingRelayState, existingRelayState, OpenSamlUtil.samlObjectToString(xmlObject)));
		}
		if (!existingRelayState.equals(incomingRelayState)) {
			throw new RequestDeniedException(String.format(
					"Invalid RelayState, existingRelayState='%s' not matching incomingRelayState='%s', blocking: %s",
					existingRelayState, incomingRelayState, OpenSamlUtil.samlObjectToString(xmlObject)));
		}
	}

	static void validateResponseIssueInstant(Response response, Instant nowOffsetDateTime,
			TrustBrokerProperties properties) {
		Instant incomingIssueInstant = response.getIssueInstant();
		if (properties.getSecurity().isValidateResponseIssueInstant()) {
			checkIssueInstantTimeRange(response, nowOffsetDateTime,
					properties.getSecurity().getNotBeforeToleranceSec(),
					properties.getSecurity().getMessageLifetimeSec(),
					incomingIssueInstant);
		}
		else {
			// DEBUG: SAML Response are short-lived but SAML2 spec does not really define enforcement, we therefore just debug
			log.debug("Response.IssueInstant validation disabled globally using " +
					"trustbroker.config.security.validateResponseIssueInstant");
		}
	}

	static void checkIssueInstantTimeRange(XMLObject xmlObject, Instant nowOffsetDateTime,
			long notBeforeToleranceSec, long notOnOrAfterToleranceSec, Instant incomingIssueInstant) {
		var duration = Duration.between(incomingIssueInstant, nowOffsetDateTime);
		long diffSec = duration.getSeconds();
		if (diffSec > notOnOrAfterToleranceSec || diffSec < notBeforeToleranceSec) {
			throw new RequestDeniedException(String.format(
					"IssueInstant invalid, incoming='%s' now='%s' diffSec=%s acceptedRangeSec=[%ds..%ds] in: %s",
					incomingIssueInstant, nowOffsetDateTime, diffSec, notBeforeToleranceSec, notOnOrAfterToleranceSec,
					OpenSamlUtil.samlObjectToString(xmlObject)));
		}
	}

	static void validateAssertionIssueInstant(Assertion assertion, Instant nowOffsetDateTime, boolean renew,
			TrustBrokerProperties properties, SecurityPolicies securityPolicies) {
		Instant incomingIssueInstant = assertion.getIssueInstant();
		if (properties.getSecurity().isValidateAssertionIssueInstant()) {
			checkIssueInstantTimeRange(assertion, nowOffsetDateTime,
					properties.getSecurity().getNotBeforeToleranceSec(),
					getNotOnOrAfterSeconds(properties, securityPolicies, renew),
					incomingIssueInstant);
		}
		else {
			// DEBUG: Assertions can be long-lived via WS-Trust. We expect Condition to signal this validity
			log.debug("Assertion.IssueInstant validation disabled globally using " +
					"trustbroker.config.security.validateAssertionIssueInstant");
		}
	}

	static void validateAssertionConsumer(String assertionConsumerServiceUrl, AcWhitelist acWhiteList,
			TrustBrokerProperties properties, XMLObject authRequest) {
		if (!properties.getSecurity().isValidateAcs()) {
			log.warn("trustbroker.config.security.validateAcs=false: All assertion consumers granted!!!");
			return;
		}
		if (acWhiteList == null || acWhiteList.getAcUrls() == null) {
			throw new RequestDeniedException(String.format(
					"Empty ACWhiteList, deny all access including acsUrl=%s", assertionConsumerServiceUrl));
		}

		if (assertionConsumerServiceUrl == null) {
			log.debug("AssertionConsumerServiceURL is null, skip ACWhitelist check");
			return;
		}

		isUrlInAcWhiteList(acWhiteList, authRequest, assertionConsumerServiceUrl);
	}

	static void isUrlInAcWhiteList(AcWhitelist acWhiteList, XMLObject authRequest, String accessedUrl) {
		try {
			// make sure we check
			if (acWhiteList == null) {
				acWhiteList = AcWhitelist.builder().build();
			}
			final var incomingUrl = new URI(accessedUrl);
			for (var check : acWhiteList.getAcNetUrls()) {
				if (UrlAcceptor.isUrlOkForAccess(incomingUrl, check)) {
					log.debug("Network access from url={} matches ACWhitelistEntry={}", accessedUrl, acWhiteList.getAcUrls());
					return;
				}
			}
			var acWhitelistForLog = CollectionUtil.toLogString(acWhiteList.getAcUrls());
			throw new RequestDeniedException(String.format(
					"Invalid url=%s not in ACWhitelist=%s required by %s",
					accessedUrl, acWhitelistForLog, OpenSamlUtil.samlObjectToString(authRequest)));
		}
		catch (URISyntaxException e) {
			var msg = String.format("Malformed URL %s from network has error='%s' triggered by: %s",
					accessedUrl, e.getMessage(), OpenSamlUtil.samlObjectToString(authRequest));
			throw new RequestDeniedException(msg);
		}
	}

	static void validateAssertionSubject(Assertion assertion, Instant nowOffsetDateTime,
			String expectedRequestId, boolean subjectConfirmationRequired, boolean renew, String expectedRecipient,
			TrustBrokerProperties properties) {

		// Subject required
		var subject = assertion.getSubject();
		if (subject == null || subject.isNil()) {
			throw new RequestDeniedException(String.format(
					"Subject missing: %s", OpenSamlUtil.samlObjectToString(assertion)));
		}
		if (subject.getNameID() == null || StringUtils.isBlank(subject.getNameID().getValue())) {
			throw new RequestDeniedException(String.format(
					"NameId missing: %s", OpenSamlUtil.samlObjectToString(assertion)));
		}
		validateAssertionSubjectConfirmations(assertion, nowOffsetDateTime,
				expectedRequestId, subjectConfirmationRequired, renew, expectedRecipient, properties);
	}

	static void validateAssertionSubjectConfirmations(Assertion assertion, Instant nowOffsetDateTime,
			String expectedRequestId, boolean subjectConfirmationRequired, boolean renew,
			String expectedRecipient, TrustBrokerProperties properties) {
		// SubjectConfirmation optional (for now)
		List<SubjectConfirmation> subjectConfirmations = assertion.getSubject().getSubjectConfirmations();
		if (subjectConfirmations == null || subjectConfirmations.isEmpty()) {
			if (subjectConfirmationRequired && properties.getSecurity().isRequireSubjectConfirmation()) {
				throw new RequestDeniedException(String.format(
						"SubjectConfirmations missing: %s", OpenSamlUtil.samlObjectToString(assertion)));
			}
			if (log.isWarnEnabled()) {
				log.warn("SubjectConfirmations missing: {}", OpenSamlUtil.samlObjectToString(assertion));
			}
			return;
		}
		for (SubjectConfirmation subjectConfirmation : subjectConfirmations) {
			// Subject confirmed by what method? In RST case we might only want to accept SubjectConfirmation
			// .METHOD_HOLDER_OF_KEY
			String acceptedSubjectConfirmations = properties.getSecurity().getAcceptSubjectConfirmationMethods();
			if (subjectConfirmation.getMethod() != null && acceptedSubjectConfirmations != null &&
					!acceptedSubjectConfirmations.contains(subjectConfirmation.getMethod())) {
				throw new RequestDeniedException(String.format(
						"SubjectConfirmation.Method missing or invalid value='%s' accepted='[%s]': %s",
						subjectConfirmation.getMethod(), acceptedSubjectConfirmations,
						OpenSamlUtil.samlObjectToString(assertion)));
			}

			// Check the subject confirmation details
			var subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
			if (subjectConfirmationData != null) {
				validateSubjectConfirmationData(subjectConfirmationData, nowOffsetDateTime, expectedRequestId, renew,
						expectedRecipient, properties, assertion);
			}
			else if (log.isInfoEnabled()) {
				log.info("SubjectConfirmationData missing: {}", OpenSamlUtil.samlObjectToString(assertion));
			}
		}
	}

	// Subject created in response to AuthnRequest? Setting inResponseTo is optional (it's usally empty)
	static void validateSubjectConfirmationData(SubjectConfirmationData subjectConfirmationData,
			Instant nowOffsetDateTime, String expectedRequestId, boolean renew, String expectedRecipient,
			TrustBrokerProperties properties, XMLObject xmlObject) {
		// still valid?
		if (properties.getSecurity().isValidateSubjectConfirmationTimestamp()) {
			validateNotBeforeAndNotAfter("SubjectConfirmationData",
					subjectConfirmationData.getNotBefore(),
					subjectConfirmationData.getNotOnOrAfter(),
					nowOffsetDateTime,
					properties.getSecurity().getNotBeforeToleranceSec(),
					getNotOnOrAfterToleranceSec(renew, properties),
					xmlObject);
		}
		else {
			log.info("trustbroker.config.security.validateSubjectConfirmationTimestamp=false: Timestamps not checked!!!");
		}
		if (properties.getSecurity().isValidateSubjectConfirmationRecipient()) {
			var subjectConfRecipient = subjectConfirmationData.getRecipient();
			if (expectedRecipient != null && subjectConfRecipient != null && !expectedRecipient.equals(subjectConfRecipient)) {
				throw new RequestDeniedException(String.format(
						"Invalid SubjectConfirmation, expectedRecipient='%s' not matching recipient='%s' in: %s",
						expectedRecipient, subjectConfirmationData.getRecipient(), OpenSamlUtil.samlObjectToString(xmlObject)));
			}
		}
		else if (subjectConfirmationData.getRecipient() != null) {
			log.debug("trustbroker.config.security.validateSubjectConfirmationRecipient=false: Recipient not checked.");
		}
		// Subject can be bound to assertion via ID
		if (properties.getSecurity().isValidateSubjectConfirmationInResponseTo()) {
			var subjectConfInRespTo = subjectConfirmationData.getInResponseTo();
			if (expectedRequestId != null && subjectConfInRespTo != null && !expectedRequestId.equals(subjectConfInRespTo)) {
				throw new RequestDeniedException(String.format(
						"Invalid SubjectConfirmation, requestId='%s' not matching subjectConfInRespTo='%s' in: %s",
						expectedRequestId, subjectConfInRespTo, OpenSamlUtil.samlObjectToString(xmlObject)));
			}
		}
		else if (subjectConfirmationData.getInResponseTo() != null) {
			log.info("trustbroker.config.security.validateSubjectConfirmationInResponseTo=false: InResponseTo not checked!!!");
		}
	}

	public static MessageValidationResult validateArtifactResolve(ArtifactResolve artifactResolve, TrustBrokerProperties properties,
			List<Credential> trustCredentials) {
		if (artifactResolve == null) {
			throw new RequestDeniedException("Missing ArtifactResolve");
		}
		if (artifactResolve.getIssuer() == null) {
			throw new RequestDeniedException(String.format("Missing issuer in artifactResolve=%s", artifactResolve.getID()));
		}
		if (artifactResolve.getArtifact() == null) {
			throw new RequestDeniedException(String.format("Missing artifact in artifactResolve=%s", artifactResolve.getID()));
		}
		if (artifactResolve.getIssueInstant() == null) {
			throw new RequestDeniedException(String.format("Missing issueInstant in artifactResolve=%s",
					artifactResolve.getID()));
		}
		Instant now = Instant.now();
		checkIssueInstantTimeRange(artifactResolve, now, properties.getSecurity().getNotBeforeToleranceSec(),
				properties.getSecurity().getNotOnOrAfterToleranceSec(), artifactResolve.getIssueInstant());
		if (artifactResolve.getDestination() == null) {
			throw new RequestDeniedException(String.format("Missing destination in artifactResolve=%s", artifactResolve.getID()));
		}
		var arServiceUrl = properties.getSaml().getArtifactResolution().getServiceUrl();
		if (!artifactResolve.getDestination().equals(arServiceUrl)) {
			throw new RequestDeniedException(
					String.format("Destination=%s in artifactResolve=%s does not match expectedDestination=%s",
					artifactResolve.getDestination(), artifactResolve.getID(), arServiceUrl));
		}
		if (artifactResolve.isSigned()) {
			return validateSignature(artifactResolve.getSignature(), trustCredentials, artifactResolve,
					SignatureContext.forArtifactBinding());
		}
		else if (properties.getSecurity().isRequireSignedArtifactResolve()) {
			 throw new RequestDeniedException(String.format("Missing signature in artifactResolve=%s", artifactResolve.getID()));
		}
		else {
			log.debug("Accepting unsigned artifactResolve={}", artifactResolve.getID());
			return MessageValidationResult.unvalidated();
		}
	}

	// ALl message related data is DateTime internalized as UTC, so use that as a reference for checking timestamps.
	// NOTE: With a non-static provider we could inject the computer clock to check data in time.
	static OffsetDateTime now() {
		return OffsetDateTime.now(ZoneOffset.UTC);
	}

}
