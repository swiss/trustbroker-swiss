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

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.security.credential.Credential;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.api.saml.dto.EncodingParameters;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.audit.dto.EventType;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.audit.service.OutboundAuditMapper;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SsoSessionIdPolicy;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.mapping.dto.QoaSpec;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.oidc.client.dto.AuthorizationCodeFlowRequest;
import swiss.trustbroker.oidc.client.service.AuthorizationCodeFlowService;
import swiss.trustbroker.saml.dto.RpRequest;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.util.WebSupport;


@Service
@AllArgsConstructor
@Slf4j
public class ClaimsProviderService {

	private final StateCacheService stateCacheService;

	private final TrustBrokerProperties trustBrokerProperties;

	private final RelyingPartySetupService relyingPartySetupService;

	private final AuditService auditService;

	private final ScriptService scriptService;

	private final QoaMappingService qoaMappingService;

	private final SamlOutputService samlOutputService;

	private final AuthorizationCodeFlowService authorizationCodeFlowService;

	private AuthnRequest createAndSignCpAuthnRequest(StateData stateData, RelyingParty relyingParty,
			SamlBinding requestedResponseBinding, QoaSpec qoaSpec, ClaimsParty claimsProvider, boolean delegateOrigin) {
		var cpIssuer = claimsProvider.getId();
		var ssoUrl = claimsProvider.getSsoUrl();
		if (ssoUrl == null) {
			throw new RequestDeniedException(String.format(
					"Missing SSOUrl for CP with cpIssuer='%s' (check SetupCP.xml)", claimsProvider.getId()));
		}

		var authnRequest = OpenSamlUtil.buildSamlObject(AuthnRequest.class);
		authnRequest.setIssueInstant(Instant.now());
		var consumerUrl = trustBrokerProperties.getSamlConsumerUrl();
		authnRequest.setDestination(ssoUrl);
		authnRequest.setID(stateData.getId()); // Tricky: cpRelayState, CpAuthnRequest.ID and SSO cookie all have the same value
		var authnRequestIssuerId = claimsProvider.getAuthnRequestIssuerId(trustBrokerProperties.getIssuer());
		log.debug("Using authnRequestIssuerId={} for cpIssuerId={}", authnRequestIssuerId, cpIssuer);
		authnRequest.setIssuer(SamlFactory.createIssuer(authnRequestIssuerId));
		authnRequest.setNameIDPolicy(SamlFactory.createNameIdPolicy(NameIDType.UNSPECIFIED));
		if (relyingParty.forwardRpProtocolBinding() && claimsProvider.forwardRpProtocolBinding() &&
				requestedResponseBinding != null && claimsProvider.isValidInboundBinding(requestedResponseBinding)) {
			log.debug("Passing on protocolBinding={} requested by RP and supported for cpIssuerId={}",
				requestedResponseBinding, cpIssuer);
			authnRequest.setProtocolBinding(requestedResponseBinding.getBindingUri());
			stateData.setRequestedResponseBinding(requestedResponseBinding);
		}
		var authnContext = createAuthnContext(stateData, qoaSpec);
		authnRequest.setRequestedAuthnContext(authnContext);

		// scopes support
		if (delegateOrigin) {
			authnRequest.setScoping(SamlFactory.createScoping(relyingParty.getId()));
			log.debug("Setting rpIssuerId={} as Scoping", relyingParty.getId());
		}

		// forcing login
		setForceAuthnAndAcUrl(stateData, authnRequest, consumerUrl, claimsProvider);

		// OnRequest hook
		scriptService.processCpOnRequest(cpIssuer, authnRequest);

		var signatureParameters = claimsProvider.getSignatureParametersBuilder()
				.credential(relyingParty.getRpSigner())
				.skinnyAssertionNamespaces(trustBrokerProperties.getSkinnyAssertionNamespaces())
				.build();
		SamlFactory.signSignableObject(authnRequest, signatureParameters);

		return authnRequest;
	}

	private void setForceAuthnAndAcUrl(StateData stateData, AuthnRequest authnRequest,  String consumerURL,
			ClaimsParty claimsProvider) {
		if (stateData.forceAuthn() || claimsProvider.forceAuthn(trustBrokerProperties.getSecurity().isForceCpAuthentication())) {
			authnRequest.setForceAuthn(true);
		}
		if (!Boolean.TRUE.equals(claimsProvider.getDisableACUrl())) {
			authnRequest.setAssertionConsumerServiceURL(consumerURL);
		}
	}

	RequestedAuthnContext createAuthnContext(StateData stateData, QoaSpec qoaSpec) {
		if (qoaSpec.contextClasses().isEmpty()) {
			// do not add an empty <samlp:RequestedAuthnContext/> to any CP side AuthnRequest (looks unclean and may be CP cares)
			return null;
		}

		// map to CP qoa model
		var requestedAuthnContext = SamlFactory.createRequestedAuthnContext(qoaSpec.contextClasses(), qoaSpec.comparison().name());

		// audit and response handling:
		stateData.setContextClasses(qoaSpec.contextClasses());
		stateData.setComparisonType(qoaSpec.comparison());

		return requestedAuthnContext;
	}

	private static void redirectUserWithRequest(AuthnRequest authnRequest, Credential credential,
			HttpServletResponse httpServletResponse, ClaimsParty claimsParty,
			StateData stateData, OutputService outputService)
	{
		var useArtifactBinding = useArtifactBinding(Optional.of(claimsParty), stateData);
		var encodingParameters = EncodingParameters.builder().useArtifactBinding(useArtifactBinding).build();
		outputService.sendRequest(authnRequest, credential, stateData.getRelayState(), claimsParty.getSsoUrl(),
				httpServletResponse, encodingParameters, DestinationType.CP);
	}

	static boolean useArtifactBinding(Optional<ClaimsParty> claimsParty, StateData stateData) {
		var requestBinding = stateData == null ? null : stateData.getSpStateData().getRequestBinding();
		var requestedResponseBinding = stateData == null ? null : stateData.getSpStateData().getRequestedResponseBinding();
		if (stateData != null) {
			log.debug("sessionId={} inbound rpRequestBinding={} requestedResponseBinding={}",
					stateData.getId(), requestBinding, requestedResponseBinding);
		}
		var useArtifactBinding = claimsParty.isPresent() && claimsParty.get().getSamlArtifactBinding() != null &&
				claimsParty.get().getSamlArtifactBinding().useArtifactBinding(requestBinding, requestedResponseBinding);
		if (useArtifactBinding) {
			log.debug(
					"Use artifact binding for AuthnRequest with cpIssuerId={} artifactBinding={} requestBinding={} "
							+ "requestedResponseBinding={} artifactBindingTrigger=session_rp_binding",
					claimsParty.get().getId(), claimsParty.get().getSamlArtifactBinding(),
					requestBinding, requestedResponseBinding);
		}
		return useArtifactBinding;
	}

	private void saveCorrelatedStateDataWithState(String cpIssuerId, String deviceID, StateData stateData) {
		// update session validity
		var now = OffsetDateTime.now();
		stateData.setIssueInstant(now.toString());
		stateData.setIssuer(cpIssuerId);
		if (deviceID != null) {
			stateData.setDeviceId(deviceID);
		}

		// set an initial session context to be sent to RP if not yet done, override in SSOService.establishSso
		if (stateData.getSsoSessionId() == null) {
			stateData.setSsoSessionId(
					SsoSessionIdPolicy.generateSsoId(false, trustBrokerProperties.getSsoSessionIdPolicy()));
		}

		// save initial data to DB
		stateCacheService.save(stateData, this.getClass().getSimpleName());
	}

	public String sendSamlToCpWithMandatoryIds(
			HttpServletRequest request,
			HttpServletResponse response,
			StateData stateData,
			String cpIssuerId) {
		// validate
		log.debug("Redirect user to CP cpIssuer={} based on rpAuthnRequestId={}",
				cpIssuerId, stateData.getSpStateData().getId());
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(cpIssuerId);
		if (StringUtils.isBlank(cpIssuerId) || claimsParty.isEmpty()) {
			var msg = String.format("Client call with missing cpIssuer='%s'", cpIssuerId);
			throw new RequestDeniedException(msg);
		}
		log.debug("Requesting cpIssuer='{}' based on rpIssuer='{}' received from client={}",
				cpIssuerId, stateData.getSpStateData().getId(),
				WebSupport.getClientHint(request, trustBrokerProperties.getNetwork()));
		return sendAuthnRequestToCp(request, response, stateData, claimsParty.get());
	}

	/**
	 * For SAML: Sends SAML POST response automatically.
	 * For OIDC: Returns redirect URL.
	 *
	 * @return redirect URL
	 */
	public String sendAuthnRequestToCp(
			HttpServletRequest request,
			HttpServletResponse response,
			StateData stateData,
			ClaimsParty claimsParty
	) {
		var cpIssuer = claimsParty.getId();

		// state from RP
		var spStateData = stateData.getSpStateData();

		// compute CP AuthnRequest for SAML and auditing
		var rpIssuer = spStateData.getIssuer();
		var context = spStateData.getRpContext();
		var rpReferrer = spStateData.getReferer();

		// script hook (may modify RpRequest context classes and comparison type)
		var claimsProviderMapping = ClaimsProvider.builder().id(cpIssuer).build(); // cannot be manipulated anyway
		var rpRequest = RpRequest.builder()
				.claimsProviders(List.of(claimsProviderMapping))
				.rpIssuer(rpIssuer)
				.requestId(spStateData.getId())
				.referer(rpReferrer)
				.contextClasses(spStateData.getContextClasses())
				.comparisonType(spStateData.getComparisonType())
				.applicationName(spStateData.getApplicationName())
				.context(context) // RP initiated internal state
				.build();
		scriptService.processCpBeforeRequest(cpIssuer, rpRequest);

		var requestedResponseBinding = spStateData.getRequestedResponseBinding();

		var claimsProviderOpt = relyingPartySetupService.getClaimsProviderSetupByIssuerId(cpIssuer);
		if (claimsProviderOpt.isEmpty()) {
			throw new RequestDeniedException(String.format(
					"Missing CP with cpIssuer='%s' (check SetupCP.xml)", StringUtil.clean(cpIssuer)));
		}
		var claimsProvider = claimsProviderOpt.get();

		// map RP Qoa model to CP Qoa model
		var cpQoaConfig = claimsProvider.getQoaConfig();
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuer, rpReferrer);

		// Compute CP side qoa to be checked when IDP returns resulting Qoa
		// Do not use any RP related settings for this because RP requirements are checked AfterProvisioning.
		var rpQoaConfig = qoaMappingService.getQoaConfiguration(spStateData, relyingParty);
		var qoaSpec = qoaMappingService.mapRequestQoasToOutbound(rpRequest.getComparisonType(), rpRequest.getContextClasses(),
				rpQoaConfig, cpQoaConfig);

		// save CP state before redirect via user-agent (saves updated CP-side qoa too)
		var deviceId = WebSupport.getDeviceId(request);
		// forward using SAML protocol depending on binding
		if (claimsParty.useSaml()) {
			var authnRequest = createAndSignCpAuthnRequest(stateData, relyingParty, requestedResponseBinding,
				qoaSpec, claimsProvider, delegateOrigin(cpIssuer));
			saveCorrelatedStateDataWithState(cpIssuer, deviceId, stateData);
			redirectUserWithRequest(authnRequest, relyingParty.getRpSigner(), response, claimsParty, stateData, samlOutputService);

			// audit
			auditAuthnRequestToCp(authnRequest, null, request, stateData);
			return null;
		}
		// forward using OIDC authorization code flow
		else {
			stateData.getSpStateData().setOidcNonce(OidcUtil.generateNonce());
			var queryParam = context.get(RpRequest.CONTEXT_OIDC_AUTHORIZATION_QUERY_PARAMETER);
			var authnCodeFlowRequest = authorizationCodeFlowService.createAuthnRequest(claimsParty, stateData, qoaSpec, queryParam);
			saveCorrelatedStateDataWithState(cpIssuer, deviceId, stateData);

			// audit
			auditAuthnRequestToCp(null, authnCodeFlowRequest, request, stateData);
			return authnCodeFlowRequest.requestUri();
		}
	}

	// Pass on rpIssuer to CP in Scoping element
	private boolean delegateOrigin(String cpIssuer) {
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(cpIssuer);
		return claimsParty.isPresent() && claimsParty.get().isDelegateOrigin();
	}

	private void auditAuthnRequestToCp(AuthnRequest authnRequest,
			AuthorizationCodeFlowRequest authnCodeFlowRequest, HttpServletRequest request,
			StateData stateData) {
		var relyingParty = stateData != null ?
				relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(stateData.getRpIssuer(),	null,	true)
				: null;
		var auditDto = new OutboundAuditMapper(trustBrokerProperties)
				.mapFrom(authnRequest)
				.mapFrom(authnCodeFlowRequest)
				.mapFrom(stateData) // overrides authnRequest conversationId if CP side
				.mapFrom(request)
				.mapFrom(relyingParty)
				.build();
		// stateData may have overridden the SAML type if it contains an IDP Response:
		auditDto.setEventType(EventType.AUTHN_REQUEST);
		auditDto.setSide(DestinationType.CP.getLabel());
		auditService.logOutboundFlow(auditDto);
	}

}
