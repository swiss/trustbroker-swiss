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

package swiss.trustbroker.wstrust.validator;

import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.xml.namespace.QName;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.soap.wssecurity.BinarySecurityToken;
import org.opensaml.soap.wstrust.RenewTarget;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestType;
import org.opensaml.soap.wstrust.WSTrustConstants;
import org.springframework.stereotype.Component;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.UrlAcceptor;
import swiss.trustbroker.common.util.WSSConstants;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.util.AssertionValidator;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.CertificateUtil;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;
import swiss.trustbroker.wstrust.dto.WsTrustValidationResult;

/**
 * Validator for WS-Trust RENEW requests.
 */
@Component
@Slf4j
public class WsTrustRenewValidator extends WsTrustBaseValidator {

	private static final String REQUEST_TYPE = RequestType.RENEW;

	private final SsoService ssoService;

	private final Optional<List<Credential>> signerTrustCredentials;

	public WsTrustRenewValidator(
			TrustBrokerProperties trustBrokerProperties, RelyingPartySetupService relyingPartySetupService, Clock clock,
			SsoService ssoService) {
		super(trustBrokerProperties, relyingPartySetupService, clock);
		this.ssoService = ssoService;
		if (enabled()) {
			this.signerTrustCredentials = Optional.of(CertificateUtil.getXtbSignerCredentials(trustBrokerProperties));
		}
		else {
			this.signerTrustCredentials = Optional.empty();
		}
	}

	@Override
	public boolean applies(RequestType requestType) {
		if (!REQUEST_TYPE.equals(requestType.getURI())) {
			return false;
		}
		if (!enabled()) {
			log.error("RequestType in RSTR requestType='{}' but RENEW disabled in configuration", requestType.getURI());
			return false;
		}
		return true;
	}

	private boolean enabled() {
		var properties = getTrustBrokerProperties();
		return properties.getWstrust() != null && properties.getWstrust().isRenewEnabled();
	}

	@Override
	public WsTrustValidationResult validate(RequestSecurityToken requestSecurityToken, SoapMessageHeader requestHeader) {
		validateHeaderElements(requestHeader);
		var headerAssertion = requestHeader.getAssertion();
		if (headerAssertion != null) {
			// not required for RENEW, but validate if present
			// (e.g. client using same wss4j configuration for ISSUE and RENEW)
			log.info("RSTR with requestType='{}' validating ignored header assertionID='{}'",
					REQUEST_TYPE, headerAssertion.getID());
			validateAssertion(headerAssertion, null, Optional.empty());
		}
		var childObjects = requestSecurityToken.getUnknownXMLObjects();
		log.debug("RSTR RENEW request - assertion is in RenewTarget");
		var assertion = extractRenewTargetAssertion(childObjects);
		var relyingParty = getRecipientRelyingParty(assertion);
		var requireSignature = getTrustBrokerProperties().getWstrust().isRenewRequireSignedRequests();
		validateSignature(requestHeader, requireSignature, relyingParty.getRpTrustCredentials());

		var session = findValidSsoSession(assertion);
		String expectedSessionId = null;
		if (session.isPresent()) {
			expectedSessionId = session.get().getSsoSessionId();
		}
		var expectedRecipient = getValidAcsUrlOrRecipient(assertion, relyingParty);
		var expectedValues = AssertionValidator.ExpectedAssertionValues.builder()
																	   .expectedIssuer(getTrustBrokerProperties().getIssuer())
																	   .expectedAudience(relyingParty.getId())
																	   .expectedSessionIndex(expectedSessionId)
																	   .expectedRecipient(expectedRecipient)
																	   .renew(true)
																	   .build();
		validateAssertion(assertion, expectedValues, signerTrustCredentials);
		validateSecurityToken(requestHeader.getSecurityToken(), relyingParty);
		return WsTrustValidationResult.builder()
									  .requestType(REQUEST_TYPE)
									  .validatedAssertion(assertion)
									  .recomputeAttributes(false)
									  .issuerId(relyingParty.getId())
									  .recipientId(relyingParty.getId())
									  .useAssertionLifetime(true)
									  .createResponseCollection(false)
									  .sessionIndex(expectedSessionId)
									  .build();
	}

	// return validated ACUrl or RP ID (which might fail assertion validation)
	private String getValidAcsUrlOrRecipient(Assertion assertion, RelyingParty relyingParty) {
		if (!getTrustBrokerProperties().getSecurity().isValidateSecurityTokenRequestAssertion()) {
			log.debug("Assertion validation disabled");
			return relyingParty.getId();
		}
		if (assertion.getSubject() == null) {
			log.debug("Missing Subject in assertion={}", assertion.getID());
			return relyingParty.getId();
		}
		if (relyingParty.getAcWhitelist() == null) {
			log.debug("Missing AC whitelist for rpIssuerId={}", relyingParty.getId());
			return relyingParty.getId();
		}
		// issuer is XTB, XTB never sets a single SubjectConfirmationData
		var acsUrl = assertion.getSubject()
						 .getSubjectConfirmations()
						 .stream()
						 .map(SubjectConfirmation::getSubjectConfirmationData)
						 .filter(Objects::nonNull)
						 .map(SubjectConfirmationData::getRecipient)
						 .filter(Objects::nonNull)
						 .findFirst();
		if (acsUrl.isEmpty()) {
			log.debug("Missing SubjectConfirmationData.Recipient in assertion={}", assertion.getID());
			return relyingParty.getId();
		}
		if (acsUrl.get().equals(relyingParty.getId())) {
			log.debug("SubjectConfirmationData.Recipient is rpIssuerId={} assertion={}",
					relyingParty.getId(), assertion.getID());
			return relyingParty.getId();
		}
		var acsUri = WebUtil.getValidatedUri(acsUrl.get());
		if (acsUri == null) {
			log.info("SubjectConfirmationData.Recipient={} does not match rpIssuerId={} and is no valid URI",
					acsUrl.get(), relyingParty.getId());
			return relyingParty.getId(); // should fail validation
		}
		for (var check : relyingParty.getAcWhitelist().getAcNetUrls()) {
			if (UrlAcceptor.isUrlOkForAccess(acsUri, check)) {
				log.debug("SubjectConfirmationData.Recipient={} matches ACWhitelistEntry={}", acsUrl.get(), check);
				return acsUrl.get();
			}
		}
		log.info("SubjectConfirmationData.Recipient={} does not match rpIssuerId={} or any ACWhitelist={} ACWhitelistNetUrls={}",
				acsUrl.get(), relyingParty.getId(),
				CollectionUtil.toLogString(relyingParty.getAcWhitelist().getAcUrls()),
				CollectionUtil.toLogString(relyingParty.getAcWhitelist().getAcNetUrls()));
		return relyingParty.getId(); // should fail validation
	}

	private void validateHeaderElements(SoapMessageHeader requestHeader) {
		log.debug("Validate WSTrust RENEW SOAP headers....");
		WsTrustHeaderValidator.validateTimestamp(requestHeader, getClock().instant(), getTrustBrokerProperties().getSecurity());
		var soapAction = WsTrustHeaderValidator.getSoapAction(requestHeader);
		// must work without action, but wrong action is an error
		if (soapAction != null && !soapAction.equals(WSTrustConstants.WSA_ACTION_RST_RENEW)) {
			throw new RequestDeniedException(String.format(
					"Action invalid in SOAP header, action='%s' expected='%s'",
					StringUtil.clean(soapAction), WSTrustConstants.WSA_ACTION_RST_RENEW));
		}
		// must work without any of these
		var messageId = requestHeader.getMessageId() != null ? requestHeader.getMessageId().getURI() : null;
		var replyToAddress = requestHeader.getReplyTo() != null && requestHeader.getReplyTo().getAddress() != null ?
				requestHeader.getReplyTo().getAddress().getURI() : null ;
		var to = requestHeader.getTo() != null ? requestHeader.getTo().getURI() : null;
		log.debug("SOAP header soapAction='{}' messageId='{}' replyToAddress='{}' to='{}'",
				soapAction, messageId, replyToAddress, to);
	}

	private static Assertion extractRenewTargetAssertion(List<XMLObject> childObjects) {
		var renewTargetQname = new QName(WSTrustConstants.WST_NS, RenewTarget.ELEMENT_LOCAL_NAME);
		RenewTarget renewTarget = OpenSamlUtil.findChildObjectByQname(childObjects, renewTargetQname);
		var renewTargetObject = renewTarget != null ? renewTarget.getUnknownXMLObject() : null;
		if (!(renewTargetObject instanceof Assertion renewAssertion)) {
			throw new RequestDeniedException(String.format(
					"RSTR with header requestType='%s' renewTarget='%s' has wrong type, expected Assertion",
					REQUEST_TYPE, renewTargetObject != null ? renewTargetObject.getClass().getName() : null));
		}
		return renewAssertion;
	}

	Optional<StateData> findValidSsoSession(Assertion assertion) {
		List<String> ssoSessionIds = extractSessionIndexes(assertion);
		var session = ssoService.findValidSsoSessionForSessionIndexes(ssoSessionIds);
		if (session.isEmpty()) {
			if (getTrustBrokerProperties().getWstrust().isRenewRequiresSsoSession()) {
				throw new RequestDeniedException(String.format(
						"RSTR with requestType='%s' - no valid SSO session with ssoSessionIds=%s",
						REQUEST_TYPE, ssoSessionIds));
			}
			log.debug("RSTR with requestType='{}' - no valid SSO session with ssoSessionIds={}", REQUEST_TYPE, ssoSessionIds);
		}
		return session;
	}

	private static List<String> extractSessionIndexes(Assertion assertion) {
		return assertion.getAuthnStatements()
						.stream()
						.map(AuthnStatement::getSessionIndex)
						.toList();
	}

	void validateSecurityToken(BinarySecurityToken securityToken, RelyingParty relyingParty) {
		if (securityToken == null) {
			if (getTrustBrokerProperties().getWstrust().isRenewRequiresSecurityToken()) {
				throw new RequestDeniedException(String.format(
						"RSTR with requestType='%s' missing header security token", REQUEST_TYPE));
			}
			log.debug("RSTR with requestType='{}' missing header security token", REQUEST_TYPE);
			return;
		}
		if (!WSSConstants.ENCODING_BASE64_BINARY.equals(securityToken.getEncodingType())) {
			throw new RequestDeniedException(String.format(
					"RSTR with requestType='%s' contains security token with encodingType='%s' expectedEncodingType=%s",
					REQUEST_TYPE, securityToken.getEncodingType(), WSSConstants.ENCODING_BASE64_BINARY));
		}
		if (!WSSConstants.VALUE_X509_V3.equals(securityToken.getValueType())) {
			throw new RequestDeniedException(String.format(
					"RSTR with requestType='%s' contains security token with valueType='%s' expectedValueType=%s",
					REQUEST_TYPE, securityToken.getValueType(), WSSConstants.VALUE_X509_V3));
		}
		validateCertificate(securityToken, relyingParty);
	}

	private static void validateCertificate(BinarySecurityToken securityToken, RelyingParty relyingParty) {
			log.debug("Received tokenType={} securityToken={}", securityToken.getValueType(), securityToken.getValue());
			X509Credential tokenCredential;
			try {
				// returned value is always an X509Credential
				tokenCredential = (X509Credential) CredentialReader.getDerOrPemCredential(
						securityToken.getValue(), WSSConstants.VALUE_X509_V3);
			}
			catch (RuntimeException ex) { // including TechnicalException
				throw new RequestDeniedException(String.format(
						"RSTR with requestType='%s' contains security token with valueType='%s' - could not parse certificate",
						REQUEST_TYPE, securityToken.getValueType()), ex);
			}
			log.debug("Received tokenType={} certificateType={}", securityToken.getValueType(),
					tokenCredential.getCredentialType());
			for (var credential : relyingParty.getRpTrustCredentials()) {
				log.debug("Checking received token against credentialType={}", credential.getCredentialType());
				if (credential instanceof X509Credential x509Credential) {
					if (x509Credential.getEntityCertificate().equals(tokenCredential.getEntityCertificate())) {
						log.info("Received tokenType={} certificateType={} matching certificate={} of rpIssuerId={}",
								securityToken.getValueType(), tokenCredential.getCredentialType(),
								x509Credential.getEntityId(), relyingParty.getId());
						return;
					}
				}
				else {
					// should not happen as they are produced with CredentialReader
					log.error("Unexpected trustCredentialType={} of rpIssuerId={}",
							credential.getCredentialType(), relyingParty.getId());
				}
			}
			throw new RequestDeniedException(String.format(
					"RSTR with requestType='%s' contains security token with valueType='%s' not matching any of the trust credentials of rpIssuerId=%s",
					REQUEST_TYPE, securityToken.getValueType(), relyingParty.getId()));
	}
}
