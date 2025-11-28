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

package swiss.trustbroker.saml.service;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.HttpClient;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.Credential;
import org.springframework.stereotype.Service;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.audit.service.InboundAuditMapper;
import swiss.trustbroker.audit.service.OutboundAuditMapper;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.dto.ArtifactPeer;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureParameters;
import swiss.trustbroker.common.saml.dto.SignatureValidationParameters;
import swiss.trustbroker.common.saml.service.ArtifactCacheService;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SoapUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ProtocolEndpoints;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.util.AssertionValidator;
import swiss.trustbroker.util.CertificateUtil;

@Service
@Slf4j
public class ArtifactResolutionService {

	private final TrustBrokerProperties trustBrokerProperties;

	private final ArtifactCacheService artifactCacheService;

	private final RelyingPartyService relyingPartyService;

	private final RelyingPartySetupService relyingPartySetupService;

	private final AuditService auditService;

	public ArtifactResolutionService(TrustBrokerProperties trustBrokerProperties, ArtifactCacheService artifactCacheService,
			RelyingPartyService relyingPartyService, RelyingPartySetupService relyingPartySetupService,
			AuditService auditService) {
		this.trustBrokerProperties = trustBrokerProperties;
		this.artifactCacheService = artifactCacheService;
		this.relyingPartyService = relyingPartyService;
		this.relyingPartySetupService = relyingPartySetupService;
		this.auditService = auditService;
	}

	public MessageContext decodeSamlArtifactRequest(HttpServletRequest request) {
		return decodeSamlArtifactRequest(request, Optional.empty());
	}

	// For testing - HttpClient is not a dependency of this class as we need to configure the trust depending on the peer
	MessageContext decodeSamlArtifactRequest(HttpServletRequest request, Optional<HttpClient> httpClient) {

		var sourceId = OpenSamlUtil.extractSourceIdFromArtifactMessage(request);
		var signArtifactResolve = trustBrokerProperties.getSecurity().isDoSignArtifactResolve();
		var requireSignedArtifactResponse = trustBrokerProperties.getSecurity().isRequireSignedArtifactResponse();
		ArtifactPeer peer;
		Optional<SignatureParameters> signatureParameters;
		SignatureValidationParameters signatureValidationParameters;
		var referrer = WebUtil.getReferer(request);
		var rp = relyingPartySetupService.getRelyingPartyByArtifactSourceIdOrReferrer(sourceId, referrer);
		if (isRelyingPartyValid(rp)) {
			peer = buildArtifactPeer(rp.get().getSamlProtocolEndpoints(), rp.get().getCertificates(), true);
			signatureParameters = buildSignatureParameters(signArtifactResolve, rp.get());
			signatureValidationParameters = buildSignatureValidationParameters(requireSignedArtifactResponse, rp.get());
		}
		else {
			var cp = relyingPartySetupService.getClaimsProviderByArtifactSourceIdOrReferrer(sourceId, referrer);
			if (isClaimsPartyValid(cp)) {
				peer = buildArtifactPeer(cp.get().getSamlProtocolEndpoints(), cp.get().getCertificates(), false);
				signatureParameters = buildSignatureParameters(signArtifactResolve, cp.get());
				signatureValidationParameters = buildSignatureValidationParameters(requireSignedArtifactResponse, cp.get());
			}
			else {
				throw new RequestDeniedException(String.format(
						"No CP or RP with ArtifactBinding ProtocolEndpoints and valid inboundMode "
								+ "sourceId=%s referrer=%s rpIssuerId=%s cpIssuerId=%s",
						sourceId, referrer, rp.isPresent() ? rp.get().getId() : null, cp.isPresent() ? cp.get().getId() : null));
			}
		}
		return OpenSamlUtil.decodeSamlArtifactMessage(request, trustBrokerProperties.getIssuer(),
				peer, signatureParameters, signatureValidationParameters, httpClient);
		// could now check if it is OK to receive this message type from an RP or CP, but it should fail later anyway if wrong
	}

	static boolean isClaimsPartyValid(Optional<ClaimsParty> cp) {
		return cp.isPresent() && cp.get().getSamlProtocolEndpoints() != null &&
				cp.get().isValidInboundBinding(SamlBinding.ARTIFACT);
	}

	static boolean isRelyingPartyValid(Optional<RelyingParty> rp) {
		return rp.isPresent() && rp.get().getSamlProtocolEndpoints() != null &&
				rp.get().isValidInboundBinding(SamlBinding.ARTIFACT);
	}

	private ArtifactPeer buildArtifactPeer(ProtocolEndpoints endpoints, Certificates certificates, boolean isRp) {
		var peerRole = isRp ? SPSSODescriptor.DEFAULT_ELEMENT_NAME : IDPSSODescriptor.DEFAULT_ELEMENT_NAME;
		String metadataUrl = null;
		String arpUrl = null;
		var arpIndex = 0;
		String proxyUrl = null;
		if (endpoints != null) {
			metadataUrl = endpoints.getMetadataUrl();
			arpUrl = endpoints.getArtifactResolutionUrl();
			if (endpoints.getArtifactResolutionIndex() != null) {
				arpIndex = endpoints.getArtifactResolutionIndex();
			}
			proxyUrl = endpoints.getProxyUrl();
		}
		var artifactResolution = trustBrokerProperties.getSaml().getArtifactResolution();
		if (proxyUrl == null) {
			proxyUrl = artifactResolution.getProxyUrl();
		}
		if (proxyUrl == null && trustBrokerProperties.getNetwork() != null) {
			proxyUrl = trustBrokerProperties.getNetwork().getProxyUrl();
		}
		var truststoreParameters = artifactResolution.getTruststore();
		if (certificates != null && certificates.getBackendTruststore() != null) {
			truststoreParameters = CertificateUtil.toKeystoreProperties(certificates.getBackendTruststore());
		}
		var keystoreParameters = artifactResolution.getKeystore();
		if (certificates != null && certificates.getBackendKeystore() != null) {
			keystoreParameters = CertificateUtil.toKeystoreProperties(certificates.getBackendKeystore());
		}
		var connectTimeout = trustBrokerProperties.getNetwork() != null ?
				Duration.ofSeconds(trustBrokerProperties.getNetwork().getBackendConnectTimeoutSec()) : null;
		log.debug("Using Truststore={} Keystore={} proxyUrl={}",
				truststoreParameters != null  ? truststoreParameters.getSignerCert() : null,
				keystoreParameters != null ? keystoreParameters.getSignerCert() : null,
				proxyUrl);
		return ArtifactPeer.builder()
				.metadataUrl(metadataUrl)
				.artifactResolutionUrl(arpUrl)
				.artifactResolutionIndex(arpIndex)
				.peerRole(peerRole)
				.proxyUrl(proxyUrl)
				.artifactResolutionTruststore(truststoreParameters)
				.artifactResolutionKeystore(keystoreParameters)
				.keystoreBasePath(trustBrokerProperties.getKeystoreBasePath())
				.connectTimeout(connectTimeout)
				.build();
	}

	private Optional<SignatureParameters> buildSignatureParameters(boolean signArtifactResolve, ClaimsParty cp) {
		if (cp.doSignArtifactResolve(signArtifactResolve)) {
			// CP has no credential configured and the original RP is not known at this point - use default signer
			log.debug("Signing ArtifactResolve with default signer for cpIssuerId={} signerCert={}",
					cp.getId(), trustBrokerProperties.getSigner().getSignerCert());
			var credential = CredentialReader.createCredential(trustBrokerProperties.getSigner());
			return Optional.of(cp.getSignatureParametersBuilder().credential(credential).build());
		}
		return Optional.empty();
	}

	private static SignatureValidationParameters buildSignatureValidationParameters(
			boolean requireSignedArtifactResponse, ClaimsParty cp) {
		return SignatureValidationParameters.of(
				cp.requireSignedArtifactResponse(requireSignedArtifactResponse), cp.getCpTrustCredential());
	}

	private static Optional<SignatureParameters> buildSignatureParameters(
			boolean signArtifactResolve, RelyingParty rp) {
		if (rp.doSignArtifactResolve(signArtifactResolve)) {
			log.debug("Signing ArtifactResolve with credential of rpIssuerId={}", rp.getId());
			return Optional.of(rp.getSignatureParametersBuilder().build());
		}
		return Optional.empty();
	}

	private static SignatureValidationParameters buildSignatureValidationParameters(
			boolean requireSignedArtifactResponse, RelyingParty rp) {
			return SignatureValidationParameters.of(
					rp.requireSignedArtifactResponse(requireSignedArtifactResponse), rp.getRpTrustCredentials());
	}

	public void resolveArtifact(HttpServletRequest request, HttpServletResponse response) {
		try {
			var artifactResolve = SoapUtil.extractSamlObjectFromEnvelope(request.getInputStream(), ArtifactResolve.class);
			var issuerId = artifactResolve.getIssuer().getValue();
			var refererUrl = WebUtil.getReferer(request);
			var artifactId = artifactResolve.getArtifact().getValue();
			log.info("Received ArtifactResolve with id={} from issuerId={} refererUrl={} for artifact={}",
					artifactResolve.getID(),
					issuerId, refererUrl, artifactId);
			var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(issuerId, refererUrl, true);
			var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(issuerId, refererUrl, true);

			validateArtifactResolve(artifactResolve, relyingParty, claimsParty);

			auditArtifactResolve(artifactResolve, relyingParty, claimsParty, request);

			var artifactResponse = createArtifactResponse(artifactResolve, issuerId, refererUrl, relyingParty, claimsParty);
			SoapUtil.sendSoap11Response(response, artifactResponse);
			log.info("Sent ArtifactResponse for artifact={} success={}", artifactResolve.getArtifact(),
					artifactResponse != null);

			auditArtifactResponse(artifactResponse, relyingParty, claimsParty, request);
			artifactCacheService.removeArtifact(artifactId);
		}
		catch (IOException ex) {
			throw new TechnicalException(String.format("Cannot process request message=%s", ex.getMessage()), ex);
		}
	}

	private ArtifactResponse createArtifactResponse(ArtifactResolve artifactResolve, String issuerId, String refererUrl,
			RelyingParty relyingParty, ClaimsParty claimsParty) {
		List<SignableSAMLObject> objectsToSign = new ArrayList<>();
		var message = artifactCacheService.retrieveArtifact(artifactResolve.getArtifact().getValue());

		var samlObject = message.isPresent() && message.get() instanceof SignableSAMLObject obj ? obj : null;
		if (samlObject != null && !samlObject.isSigned() && trustBrokerProperties.getSecurity().isDoSignSuccessResponse()) {
			log.debug("SAML object of type={} is not yet signed", samlObject.getClass().getName());
			objectsToSign.add(samlObject);
		}
		var artifactResponse = SamlFactory.createArtifactResponse(artifactResolve, message, trustBrokerProperties.getIssuer());
		if (trustBrokerProperties.getSecurity().isDoSignArtifactResponse()) {
			log.debug("ArtifactResponse is to be signed");
			objectsToSign.add(artifactResponse);
		}
		if (!objectsToSign.isEmpty()) {
			signSamlObjects(issuerId, relyingParty, claimsParty, samlObject, refererUrl, objectsToSign);
		}
		return artifactResponse;
	}

	private void validateArtifactResolve(ArtifactResolve artifactResolve, RelyingParty relyingParty, ClaimsParty claimsParty) {
		List<Credential> trustCredentials = Collections.emptyList();
		if (relyingParty != null) {
			log.debug("ArtifactResolve issued by rpIssuerId={}", relyingParty.getId());
			trustCredentials = relyingParty.getRpTrustCredentials();
		}
		else if (claimsParty != null) {
			log.debug("ArtifactResolve issued by cpIssuerId={}", claimsParty.getId());
			trustCredentials = claimsParty.getCpTrustCredential();
		}
		AssertionValidator.validateArtifactResolve(artifactResolve, trustBrokerProperties, trustCredentials);
	}

	private void signSamlObjects(String issuerId, RelyingParty relyingPartyByIssuerId, ClaimsParty claimsProviderByIssuerId,
			SignableSAMLObject message, String refererUrl, List<SignableSAMLObject> samlObjects) {
		var params = getSignatureParameters(issuerId, relyingPartyByIssuerId, claimsProviderByIssuerId, message, refererUrl);
		params.setSkinnyAssertionNamespaces(trustBrokerProperties.getSkinnyAssertionNamespaces());
		for (var samlObject : samlObjects) {
			SamlFactory.signSignableObject(samlObject, params);
		}
	}

	private SignatureParameters getSignatureParameters(String issuerId, RelyingParty relyingPartyByIssuerId,
			ClaimsParty claimsProviderByIssuerId, SignableSAMLObject message, String refererUrl) {
		SignatureParameters params;
		// ARP returning in SAML Request must be from CP, Response from RP, if we did not find the artifact it could be RP
		// or CP (we could provide separate ARP endpoints in the metadata for the two cases)
		// expect a matching RP issuer for responses
		if (relyingPartyByIssuerId != null && (message instanceof StatusResponseType || message == null)) {
			log.debug("Signing objects for rpIssuerId={}", relyingPartyByIssuerId.getId());
			params = relyingPartyByIssuerId.getSignatureParametersBuilder().build();
		}
		// expect a matching CP issuer for requests
		else if (claimsProviderByIssuerId != null && (message instanceof RequestAbstractType || message == null)) {
			params = getSignatureParametersForCp(issuerId, message, refererUrl, relyingPartyByIssuerId,
					claimsProviderByIssuerId);
		}
		// Fallback to message signature - can happen if SamlMock issuer has the wrong role (CP vs. RP)
		else if (message != null && message.isSigned() && message.getSignature() != null) {
			params = SignatureParameters.builderOf(message.getSignature()).build();
			// This assumes ArtifactResolve and message are for the same recipient (which we could check)
			log.debug("Signing objects based on signature of contained messageType={}", message.getClass().getName());
		}
		else {
			throw new RequestDeniedException(
					String.format("Could not find RP or CP by issuerId=%s refererUrl=%s", issuerId, refererUrl));
		}
		// Fallback credential if either of the above did not yield a credential (missing in config or signature w/o credential)
		if (params.getCredential() == null) {
			log.info("Fallback to default signer for issuerId={} message={}", issuerId,
					message != null ? message.getClass().getName() : null);
			var credential = CredentialReader.createCredential(trustBrokerProperties.getSigner());
			params.setCredential(credential);
		}
		return params;
	}

	private SignatureParameters getSignatureParametersForCp(String issuerId, SignableSAMLObject message,
			String refererUrl, RelyingParty relyingParty, ClaimsParty claimsParty) {
		SignatureParameters params;
		// need the RP for the certificate
		var rpIssuerId = relyingPartyService.findRelyingPartyIdForTrustbrokerSamlObject(message);
		if (relyingParty == null && rpIssuerId != null && !rpIssuerId.equals(issuerId)) {
			relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuerId, refererUrl, true);
		}
		Credential credential = null;
		if (relyingParty != null) {
			log.debug("Using signer from rpIssuerId={} for cpIssuerId={} ", relyingParty.getId(), claimsParty.getId());
			credential = relyingParty.getRpSigner();
		}
		params = claimsParty.getSignatureParametersBuilder().credential(credential).build();
		log.debug("Signing objects for cpIssuerId={}", claimsParty.getId());
		return params;
	}

	private void auditArtifactResolve(ArtifactResolve artifactResolve, RelyingParty relyingParty,
			ClaimsParty claimsParty, HttpServletRequest request) {
		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(artifactResolve)
				.mapFrom(request)
				.mapFrom(relyingParty)
				.mapFrom(claimsParty)
				.build();
		auditService.logInboundFlow(auditDto);
	}

	private void auditArtifactResponse(ArtifactResponse artifactResponse, RelyingParty relyingParty,
			ClaimsParty claimsParty, HttpServletRequest request) {
		var auditDto = new OutboundAuditMapper(trustBrokerProperties)
				.mapFrom(artifactResponse)
				.mapFrom(request)
				.mapFrom(relyingParty)
				.mapFrom(claimsParty)
				.build();
		auditService.logOutboundFlow(auditDto);
	}
}
