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

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.xml.security.utils.EncryptionConstants;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.accessrequest.dto.AccessRequestHttpData;
import swiss.trustbroker.api.accessrequest.service.AccessRequestService;
import swiss.trustbroker.api.idm.dto.IdmProvisioningRequest;
import swiss.trustbroker.api.idm.service.IdmProvisioningService;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionResult;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.api.saml.dto.EncodingParameters;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.audit.service.InboundAuditMapper;
import swiss.trustbroker.audit.service.OutboundAuditMapper;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.EncryptionUtil;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.common.util.ProcessUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SsoSessionIdPolicy;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Encryption;
import swiss.trustbroker.federation.xmlconfig.EncryptionKeyInfo;
import swiss.trustbroker.federation.xmlconfig.EncryptionKeyPlacement;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SloProtocol;
import swiss.trustbroker.homerealmdiscovery.dto.ProfileRequest;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.DefaultIdmStatusPolicyCallback;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.service.ClaimsMapperService;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.mapping.util.AttributeFilterUtil;
import swiss.trustbroker.mapping.util.QoaMappingUtil;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.saml.dto.ResponseParameters;
import swiss.trustbroker.saml.dto.ResponseStatus;
import swiss.trustbroker.saml.util.AssertionValidator;
import swiss.trustbroker.saml.util.ResponseFactory;
import swiss.trustbroker.saml.util.SamlValidationUtil;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.HrdSupport;
import swiss.trustbroker.util.WebSupport;

@Service
@AllArgsConstructor
@Slf4j
public class RelyingPartyService {

	@RequiredArgsConstructor(staticName = "of")
	private static class LogoutParams {

		final HttpServletRequest request;

		final HttpServletResponse response;

		final LogoutRequest logoutRequest;

		final String requestRelayState;

		final String requestReferrer;

		final SignatureContext signatureContext;

		final OutputService outputService;
	}

	private final StateCacheService stateCacheService;

	private final TrustBrokerProperties trustBrokerProperties;

	private final RelyingPartySetupService relyingPartySetupService;

	private final List<IdmQueryService> idmQueryServices;

	private final List<IdmProvisioningService> idmProvisioningServices;

	private final ProfileSelectionService profileSelectionService;

	private final SsoService ssoService;

	private final AuditService auditService;

	private final ScriptService scriptService;

	private final ApiSupport apiSupport;

	private final AccessRequestService accessRequestService;

	private final ResponseFactory responseFactory;

	private final UnknownUserPolicyService unknownUserPolicyService;

	private final QoaMappingService qoaService;

	private final ClaimsMapperService claimsMapperService;

	private void getAttributesFromIdm(CpResponse cpResponse, String requestIssuer, boolean audited) {
		var cpIssuer = cpResponse.getIssuer();
		var relyingPartyConfig = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(requestIssuer, null);
		var callback = new DefaultIdmStatusPolicyCallback(cpResponse);
		var originalUserDetailCount = 0;
		var originalPropertiesCount = 0;
		Set<String> lookupStores = new HashSet<>();
		for (var idmService : idmQueryServices) {
			log.debug("IDM call: issuer={} nameID={} requestIssuer={}", cpIssuer, cpResponse.getNameId(), requestIssuer);
			var queryResponse = audited ?
					idmService.getAttributesAudited(relyingPartyConfig, cpResponse, cpResponse.getIdmLookup(), callback) :
					idmService.getAttributes(relyingPartyConfig, cpResponse, cpResponse.getIdmLookup(), callback);
			if (queryResponse.isPresent()) {
				DefinitionUtil.mapAttributeList(queryResponse.get().getUserDetails(), cpResponse.getUserDetails());
				originalUserDetailCount += queryResponse.get().getOriginalUserDetailsCount();
				DefinitionUtil.mapAttributeListIgnoringSource(queryResponse.get().getProperties(), cpResponse.getProperties());
				originalPropertiesCount += queryResponse.get().getOriginalPropertiesCount();
				cpResponse.getAdditionalIdmData().putAll(queryResponse.get().getAdditionalData());
				lookupStores.addAll(queryResponse.get().getQueriedStores());
			}
		}
		cpResponse.setOriginalUserDetailsCount(originalUserDetailCount);
		cpResponse.setOriginalPropertiesCount(originalPropertiesCount);
		cpResponse.setQueriedStores(lookupStores);
	}

	public void setProperties(CpResponse cpResponse) {
		if (cpResponse.getIssuer() != null) {
			cpResponse.addPropertyIfMissing(CoreAttributeName.HOME_REALM.getName(),
					CoreAttributeName.HOME_REALM.getNamespaceUri(), cpResponse.getIssuer());
		}

		// If CP homeName is constant, or it was changes by the script(see RelyingPartySetupService.getHomeName), otherwise CP
		// attributes supporting OriginalIssuer wins
		var attribute = cpResponse.getAttribute(CoreAttributeName.HOME_NAME.getNamespaceUri());
		if (cpResponse.getHomeName() != null && !cpResponse.getHomeName().equals(attribute)) {
			cpResponse.addPropertyIfMissing(CoreAttributeName.HOME_NAME.getName(),
					CoreAttributeName.HOME_NAME.getNamespaceUri(), cpResponse.getHomeName());
		}

		var clientExtId = computeClientExtId(cpResponse);
		if (clientExtId != null) {
			cpResponse.addPropertyIfMissing(CoreAttributeName.ISSUED_CLIENT_EXT_ID.getName(),
					CoreAttributeName.ISSUED_CLIENT_EXT_ID.getNamespaceUri(), clientExtId);
		}

		var cpAuthLevel = relyingPartySetupService.getClaimsProviderSetupByIssuerId(cpResponse.getIssuer(), "")
												  .getAuthLevel();
		if (cpResponse.getAuthLevel() == null) {
			if (cpAuthLevel == null) {
				cpAuthLevel = qoaService.getUnspecifiedAuthLevel().getName();
			}
			cpResponse.setAuthLevel(cpAuthLevel);
			cpResponse.addPropertyIfMissing(CoreAttributeName.AUTH_LEVEL.getName(),
					CoreAttributeName.AUTH_LEVEL.getNamespaceUri(), cpAuthLevel);
		}

		var conversationId = TraceSupport.getOwnTraceParent();
		cpResponse.addPropertyIfMissing(CoreAttributeName.CONVERSATION_ID.getName(),
				CoreAttributeName.CONVERSATION_ID.getNamespaceUri(), conversationId);
	}

	static void adjustSsoSessionIdProperty(StateData stateData, CpResponse cpResponse) {
		if (stateData != null && stateData.getSsoSessionId() != null) {
			cpResponse.setProperty(CoreAttributeName.SSO_SESSION_ID.getName(),
					CoreAttributeName.SSO_SESSION_ID.getNamespaceUri(),
					stateData.getSsoSessionId());
		}
	}

	private String computeClientExtId(CpResponse cpResponse) {
		String clientExtId = cpResponse.getClientExtId();
		if (clientExtId != null) {
			return clientExtId;
		}
		Optional<String> queryClientExtId = relyingPartySetupService.getClientExtId(cpResponse.getIdmLookup());

		return queryClientExtId.orElse(null);
	}

	// Handling direct response from CP with data from IDM
	public String sendResponseWithSamlResponseFromCp(OutputService outputService, ResponseData<Response> responseData,
			CpResponse cpResponse, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
		SamlValidationUtil.validateRelayState(responseData);
		var cpStateData = stateCacheService.find(responseData.getRelayState(), this.getClass().getSimpleName());
		return sendResponseWithSamlResponseFromCp(outputService, responseData, cpStateData, cpResponse,
				httpServletRequest, httpServletResponse);
	}

	public String sendResponseWithSamlResponseFromCp(OutputService outputService, ResponseData<Response> responseData,
			StateData cpStateData, CpResponse cpResponse,
			HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
		// state
		var cpRequestId = cpResponse.getInResponseTo();
		log.debug("RP response SUCCESS forwarding from cpIssuer={} with cpRequestId={}",
				cpResponse.getIssuer(), cpRequestId);

		// bailout cases, update in case of SSO
		cpStateData.setRequestBinding(responseData.getBinding());

		// CP side auditing
		// To have a consistent conversationId we need the state but that one could have gone (we might lose the audit here)
		// on the other hand with INTERACTIVE profile selection we need to prevent auditing twice when /api/v1/hrd/profile is
		// called by the user selecting the wanted profile.
		auditResponseFromCp(httpServletRequest, responseData.getResponse(), cpResponse, cpStateData);

		// fetch data and have a first response with all data, profile selection follows
		fetchIdmData(cpResponse, cpStateData, cpResponse.getClientName(), true);

		// update data if provisioning modified the IDM
		if (provisionIdm(cpResponse)) {
			fetchIdmData(cpResponse, cpStateData, cpResponse.getClientName(), false);
		}

		// block CP users not found in IDM
		unknownUserPolicyService.applyUnknownUserPolicy(cpResponse, getClaimsParty(cpResponse));

		// before generating any further IDM data (e.g. AccessRequest) allow hook to do e.g. custom Qoa checks
		scriptService.processCpAfterProvisioning(cpResponse, cpResponse.getIssuer());
		scriptService.processRpAfterProvisioning(cpResponse, cpResponse.getRpIssuer(), cpResponse.getRpReferer());

		// validate with RP Qoa requirement
		if (!cpResponse.isAborted()) {
			validateRpQoaRequirement(cpStateData, cpResponse);
		}

		// process CP response
		cpStateData.setCpResponse(cpResponse);
		return sendSuccessSamlResponseToRp(outputService, responseData,
				cpStateData, cpStateData.getDeviceId(), httpServletRequest, httpServletResponse);
	}

	public void validateRpQoaRequirement(StateData cpStateData, CpResponse cpResponse) {
		var spStateData = cpStateData.getSpStateData();
		var requestIssuer = spStateData.getIssuer();
		var requestReferer = spStateData.getReferer();
		Map<String, Integer> globalMapping = trustBrokerProperties.getQoaMap();
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(
				requestIssuer, requestReferer);
		var rpQoaConf = qoaService.getQoaConfiguration(cpStateData.getSpStateData(), relyingParty);
		rpQoaConf = rpQoaConf != null ? rpQoaConf : new QoaConfig(null, null);

		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(cpResponse.getIssuerId()).orElseThrow(() ->
				new TechnicalException(String.format("Could not find cpIssuerId=%s", cpResponse.getIssuer())));
		var cpQoaConf = claimsParty != null ? claimsParty.getQoaConfig() : new QoaConfig(null, null);

		var rpComparison = QoaMappingUtil.getRpComparison(cpStateData, rpQoaConf.config());
		var rpContextClasses = QoaMappingUtil.getRpContextClasses(cpStateData, rpQoaConf.config());

		// map before validation to apply downgrade
		// NOTE: NoAuthnContext status responder towards relying party is not implemented (cpResponse.abort() handling here)
		var mappedQoas = qoaService.mapResponseQoasToOutbound(cpResponse.getContextClasses(), cpQoaConf, rpComparison, rpContextClasses, rpQoaConf);
		for (String qoa : mappedQoas) {
			AssertionValidator.validateQoaRequirement(qoa, rpQoaConf, rpComparison, rpContextClasses, globalMapping, cpQoaConf.issuerId());
		}
	}

	// return true if any modifications (create/update) were performed
	private boolean provisionIdm(CpResponse cpResponse) {
		var claimsProvider = relyingPartySetupService.getClaimsProviderSetupByIssuerId(cpResponse.getIssuerId()).orElseThrow(() ->
							 new TechnicalException(String.format("Could not find cpIssuerId=%s", cpResponse.getIssuer())));
		if (!claimsProvider.getProvision().isEnabled()) {
			return false;
		}
		String homeName = null;
		String homeNameMigrationAlias = null;
		if (claimsProvider.getHomeName() != null) {
			homeName = claimsProvider.getHomeName().getName();
			homeNameMigrationAlias = claimsProvider.getHomeName().getMigrationAlias();
		}
		String accountSource = null;
		if (claimsProvider.getAccountSource() != null) {
			accountSource = claimsProvider.getAccountSource().getValue();
		}
		var provisioningAttributes = CollectionUtil.findListByPredicate(
				claimsProvider.getAttributesSelection() != null ?
						claimsProvider.getAttributesSelection().getDefinitions() : null,
				Definition::isProvisioningAttribute);
		var identifyingClaim = CollectionUtil.findSingleValueByPredicate(
				claimsProvider.getAttributesSelection() != null ?
						claimsProvider.getAttributesSelection().getDefinitions() : null,
				Definition::isProvisioningIdAttribute).orElse(null);
		var qoa = qoaService.getMaxQoaOrder(cpResponse.getContextClasses(), claimsProvider.getQoaConfig());
		List<String> modes = claimsProvider.getProvisioning() != null ?
				Collections.unmodifiableList(claimsProvider.getProvisioning().getModes()) :
				Collections.emptyList();
		var provisioningRequest = IdmProvisioningRequest.builder()
				.identifyingClaim(identifyingClaim)
				.homeName(homeName)
				.homeNameMigrationAlias(homeNameMigrationAlias)
				.accountSource(accountSource)
				.cpSubjectNameId(cpResponse.getNameId())
				.cpAttributes(cpResponse.getOriginalAttributes())
				.idmAttributes(cpResponse.getUserDetailMap())
				.provisioningAttributes(provisioningAttributes)
				.cpAuthenticationQoa(qoa)
				.logOnly(claimsProvider.getProvision().isDetectOnly())
				.modes(modes)
				.additionalData(cpResponse.getAdditionalIdmData())
				.queriedStores(cpResponse.getQueriedStores())
				.build();
		boolean result = false;
		for (var idmProvisioningService : idmProvisioningServices) {
			var provisioningResult = idmProvisioningService.createOrUpdateUser(provisioningRequest);
			log.debug("Provisioning to service={} resulted in status={} userId={}",
					idmProvisioningService.getClass().getName(), provisioningResult.getStatus(),
					provisioningResult.getUserId());
			result |= provisioningResult.getStatus().isModified();
		}
		return result;
	}

	// Handling all cases (direct CpResponse from CP or interactive profile selection from UI)
	@SuppressWarnings("java:S107")
	String sendSuccessSamlResponseToRp(OutputService outputService, ResponseData<Response> responseData,
			StateData idpStateData, String incomingDeviceId,
			HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
		var cpResponse = idpStateData.getCpResponse();

		// bailout in case script hook did an abort (SAML response with responder status, no profile selection etc.)
		if (cpResponse.isAborted()) {
			return sendFailedSamlResponseToRp(outputService, responseData, httpServletRequest, httpServletResponse, idpStateData);
		}

		// prepare session switch for SSO if needed, this one only makes sure we have the ssoSessionId in the response
		var relyingParty = getRelyingParty(idpStateData);
		ProfileSelectionResult psResult = null;
		// do initial profile selection if not yet decided already by user
		// reset existing selection if needed, based on fresh IDM data
		refreshUserDataIfNeeded(idpStateData, null, relyingParty);
		if (idpStateData.getSelectedProfileExtId() == null) {
			var profileSelectionData = ProfileSelectionData.builder()
														   .profileSelectionProperties(relyingParty.getProfileSelection())
														   .exchangeId(responseData.getRelayState())
														   .applicationName(idpStateData.getRpApplicationName())
														   .oidcClientId(idpStateData.getRpOidcClientId())
														   .build();
			psResult = profileSelectionService.doInitialProfileSelection(
					profileSelectionData, relyingParty, cpResponse, idpStateData);
			if (psResult.getRedirectUrl() != null) {
				// we need to remember the state here, so we can continue after the user has selected account/profile
				stateCacheService.save(idpStateData, this.getClass().getSimpleName());
				return psResult.getRedirectUrl();
			}
			idpStateData.setSelectedProfileExtId(psResult.getSelectedProfileId());
		}

		var claimsParty = getClaimsParty(cpResponse);
		var arRedirect = performAccessRequestIfRequired(httpServletRequest, relyingParty, claimsParty, idpStateData, null);
		if (arRedirect != null) {
			// save done by public performAccessRequestIfRequired
			return arRedirect;
		}

		// Return from SSO step-up

		var subjectNameId = cpResponse.getNameId();
		var stateByCookieId = ssoService.findValidStateFromCookies(
				relyingParty, claimsParty, subjectNameId, httpServletRequest.getCookies());
		var stateDataForResponse = stateByCookieId.orElse(null);
		if (stateDataForResponse != null) {
			log.debug("Session state={} found based on cookie, checking SSO for incomingDeviceId={}",
					stateDataForResponse.getId(), incomingDeviceId);
			if (ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, stateDataForResponse, idpStateData,
					incomingDeviceId, claimsParty.getId())) {
				ssoService.completeDeviceInfoPreservingStateForSso(stateDataForResponse, idpStateData, relyingParty);
				log.info("Joined SSO sessionId={} for authnSessionId={}", stateDataForResponse.getId(), idpStateData.getId());
			}
			else {
				log.info("Cannot join SSO sessionId={} for authnSessionId={} caused by failed CP post-condition"
								+ " from cpIssuer={} providing cpCtx='{}' where rpIssuer={} requested rpCtx='{}'",
						stateDataForResponse.getId(), idpStateData.getId(),
						cpResponse.getIssuer(), cpResponse.getContextClasses(),
						idpStateData.getRpIssuer(), idpStateData.getRpContextClasses());
				stateDataForResponse = idpStateData;
			}
		}
		else {
			log.debug("No SSO state found for rpIssuerId={} cpIssuerId={} subjectNameId={}",
					relyingParty.getId(), claimsParty.getId(), subjectNameId);
		}

		// SSO session switch or non-SSO session discard after everything was done
		if (stateDataForResponse == null) {
			stateDataForResponse = idpStateData;
			adjustSsoSessionIdForRpResponse(relyingParty, idpStateData, cpResponse);
			establishSsoOrInvalidateState(relyingParty, claimsParty, idpStateData, true);
		}
		else {
			invalidateStateData(idpStateData, true);
		}

		// Apply profile selection after the CPResponse has the final UserDetails list
		var profileSelectionData = ProfileSelectionData.builder()
													   .profileSelectionProperties(relyingParty.getProfileSelection())
													   .selectedProfileId(idpStateData.getSelectedProfileExtId())
													   .enforceSingleProfile(true)
													   .exchangeId(idpStateData.getSpStateData().getRelayState())
													   .applicationName(idpStateData.getRpApplicationName())
													   .oidcClientId(idpStateData.getRpOidcClientId())
													   .build();
		psResult = profileSelectionService.doFinalProfileSelection(profileSelectionData, relyingParty, cpResponse,
				idpStateData);

		// send
		var encodingParameters = buildEncodingParameters(relyingParty, stateDataForResponse, responseData.getBinding());
		var samlResponse = createSignedSamlResponse(cpResponse, stateDataForResponse, psResult);

		// handle an error display with continue to RP (script hook result)
		if (samlResponse == null) {
			return preserveStateAndGetRedirectUriForAbortedResponse(cpResponse, stateDataForResponse);
		}

		var resultResponseData = ResponseData.of(samlResponse, null, null);
		sendResponseToRp(resultResponseData, cpResponse, Optional.of(stateDataForResponse), httpServletRequest,
				httpServletResponse, null, encodingParameters, outputService);
		return null;
	}

	// reset profile selection if selected profile is not in IDM result
	private void resetStaleProfileSelection(boolean newParticipant, String originalParticipantId, StateData stateData,
											CpResponse cpResponse, RelyingParty relyingParty) {
		if (stateData.getSelectedProfileExtId() == null) {
			log.debug("Reset selectedProfileId not required for rpIssuer={} on stateData={}",
					relyingParty.getId(), stateData.getId());
			return;
		}
		// new participant means new profile selection
		if (newParticipant) {
			log.info("Reset selectedProfileId={} due to change from previousRpIssuer={} to rpIssuer={}",
					stateData.getSelectedProfileExtId(), originalParticipantId, relyingParty.getId());
			stateData.setSelectedProfileExtId(null);
			return;
		}
		// existing participant doing a stepup receive the same profile with potentially changed roles from IDM
		var profileSelectionData = ProfileSelectionData.builder()
													   .profileSelectionProperties(relyingParty.getProfileSelection())
													   .exchangeId(stateData.getRpRelayState())
													   .applicationName(stateData.getRpApplicationName())
													   .oidcClientId(stateData.getRpOidcClientId())
													   .selectedProfileId(stateData.getSelectedProfileExtId())
													   .build();
		if (!profileSelectionService.isValidSelectedProfile(profileSelectionData, cpResponse)) {
			log.info("Reset selectedProfileId={} due to new IDM data for rpIssuer={}",
					stateData.getSelectedProfileExtId(), cpResponse.getRpIssuer());
			stateData.setSelectedProfileExtId(null);
		}
	}

	public String performAccessRequestWithDataRefreshIfRequired(HttpServletRequest httpServletRequest,
			RelyingParty relyingParty, ClaimsParty claimsParty, StateData idpStateData, StateData stateDataByAuthnReq) {
		// check freshness of data within the one session we have - need to have the right tenant for the check
		refreshUserDataIfNeeded(idpStateData, stateDataByAuthnReq, relyingParty);
		return performAccessRequestIfRequired(httpServletRequest, relyingParty, claimsParty, idpStateData, stateDataByAuthnReq);
	}

	private String performAccessRequestIfRequired(HttpServletRequest httpServletRequest,
			RelyingParty relyingParty, ClaimsParty claimsParty, StateData idpStateData, StateData stateDataByAuthnReq) {
		if (HrdSupport.requestFromTestApplication(httpServletRequest, trustBrokerProperties)) {
			// no access request for automated tests (OIDC and SAML)
			log.info("Skipping access request check for call from test application");
			return null;
		}
		var httpData = AccessRequestHttpData.of(httpServletRequest);
		var stateToUpdate = getStateToUpdateFromIdm(idpStateData, stateDataByAuthnReq);
		var arResult = accessRequestService.performAccessRequestIfRequired(httpData, relyingParty, idpStateData,
				() -> fetchIdmData(idpStateData.getCpResponse(), stateToUpdate, relyingParty.getClientName(), true));
		// initiate AR to maybe create new data in IDM
		if (arResult.getRedirectUrl() != null) {
			stateCacheService.save(idpStateData, this.getClass().getSimpleName());
			return arResult.getRedirectUrl();
		}
		// continue with normal result, but keep session
		if (arResult.isRetainSession()) {
			ssoService.establishImplicitSso(relyingParty, claimsParty, idpStateData);
		}
		return null;
	}

	// provide either StateData with original request binding stored in spStateData, or binding from current request
	static boolean useArtifactBinding(RelyingParty relyingParty, StateData stateData, SamlBinding inboundSamlBinding) {
		var trigger = "inbound_binding";
		var binding = inboundSamlBinding;
		var requestedResponseBinding = stateData != null ? stateData.getSpStateData().getRequestedResponseBinding() : null;
		if (binding != SamlBinding.ARTIFACT && stateData != null) {
			trigger = "session_rp_binding";
			binding = stateData.getSpStateData().getRequestBinding();
			if (binding != SamlBinding.ARTIFACT) {
				trigger = "session_cp_binding";
				binding = stateData.getRequestBinding();
			}
			log.debug("requestBinding={} sessionId={} inbound rpRequestBinding={} cpRequestBinding={} requestedResponseBinding={}"
							+ "resulting in binding={} from artifactBindingTrigger={} ",
					inboundSamlBinding, stateData.getId(), stateData.getSpStateData().getRequestBinding(),
					stateData.getRequestBinding(), requestedResponseBinding, binding, trigger);
		}
		else {
			log.debug("requestBinding={} requestedResponseBinding={} (session not checked)",
					inboundSamlBinding, requestedResponseBinding);
		}
		var useArtifactBinding = relyingParty.getSamlArtifactBinding() != null &&
				relyingParty.getSamlArtifactBinding().useArtifactBinding(binding, requestedResponseBinding);
		if (useArtifactBinding) {
			log.debug(
					"Use artifact binding for response with rpIssuerId={} artifactBinding={} "
							+ "binding={} requestedResponseBinding={} artifactBindingTrigger={}",
					relyingParty.getId(), relyingParty.getSamlArtifactBinding(),
					binding, requestedResponseBinding, trigger);
		}
		var actualBinding = useArtifactBinding ? SamlBinding.ARTIFACT : SamlBinding.POST; // response is never REDIRECT
		if (!actualBinding.compatibleWithRequestedBinding(requestedResponseBinding)) {
			var requestId = stateData != null ? stateData.getSpStateData().getId() : null;
			throw new TechnicalException(
					String.format("AuthnRequest=%s requested protocolBinding=%s, but would use responseBinding=%s" +
									" for rpIssuerId=%s - HINT: Check ArtifactBinding=%s in SetupRP.xml",
							requestId, requestedResponseBinding, actualBinding, relyingParty.getId(),
							relyingParty.getSamlArtifactBinding()));
		}
		return useArtifactBinding;
	}

	private void updateCpResponseForSso(CpResponse cpResponse, StateData spStateData, String clientName) {
		// remove old attributes
		cpResponse.getUserDetails().clear();
		cpResponse.getProperties().clear();

		// reset original attribute list
		var notProcessedAttributes = cpResponse.getOriginalAttributes();
		if (notProcessedAttributes != null) {
			cpResponse.setAttributes(new HashMap<>(notProcessedAttributes));
		}

		// IDM data
		var requestIssuer = spStateData.getIssuer();
		var requestReferer = spStateData.getReferer();
		cpResponse.setClientName(clientName);
		cpResponse.setRpIssuer(requestIssuer);
		cpResponse.setRpContext(spStateData.getRpContext());

		// scripts BeforeIdm CP side (called per IDM invocation i.e. for IDMLookup, JIT and AccessRequest reload)
		scriptService.processCpBeforeIdm(cpResponse, null, cpResponse.getIssuer(), requestReferer);

		// filter CP attributes
		var cpAttributeDefinitions = relyingPartySetupService.getClaimsProviderSetupByIssuerId(cpResponse.getIssuer(), "")
				.getAttributesDefinitions();
		ResponseFactory.filterCpAttributes(cpResponse, cpAttributeDefinitions, trustBrokerProperties.getSaml());

		// make IDM context available RP side scripting
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(requestIssuer, requestReferer);
		var idmLookUp = relyingPartySetupService.getIdmLookUp(relyingParty);
		idmLookUp.ifPresent(idmLookup -> cpResponse.setIdmLookup(idmLookup.shallowClone()));
		cpResponse.setClientExtId(relyingPartySetupService.getRpClientExtId(relyingParty));

		// scripts BeforeIdm RP side
		scriptService.processRpBeforeIdm(cpResponse, null, requestIssuer, requestReferer);
	}

	public void filterPropertiesSelection(CpResponse cpResponse, String requestIssuer, String requestReferer) {
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(requestIssuer, requestReferer);
		var propertiesAttrSelection = relyingParty.getPropertiesSelection();
		var claimsSelection = relyingParty.getClaimsSelection();
		filterPropertiesSelection(cpResponse, propertiesAttrSelection, claimsSelection);
	}

	public void filterPropertiesSelection(CpResponse cpResponse, AttributesSelection propertiesSelection,
			AttributesSelection claimsSelection) {
		var properties = cpResponse.getProperties();
		cpResponse.setProperties(AttributeFilterUtil.filterProperties(properties, propertiesSelection, claimsSelection));
	}

	public String sendFailedSamlResponseToRp(
			OutputService outputService, ResponseData<Response> responseData, HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, CpResponse cpResponse) {
		var idpStateData = stateCacheService.find(responseData.getRelayState(), this.getClass().getSimpleName());
		idpStateData.setCpResponse(cpResponse);
		return sendFailedSamlResponseToRp(outputService, responseData, httpServletRequest, httpServletResponse, idpStateData);
	}

	String sendFailedSamlResponseToRp(
			OutputService outputService, ResponseData<Response> responseData, HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, StateData idpStateData) {
		var cpResponse = idpStateData.getCpResponse();
		var idpRequestId = cpResponse.getInResponseTo();
		SamlValidationUtil.validateRelayState(responseData);
		log.debug("RP response FAILED forwarding from cpIssuer={} with idpRequestId={}", cpResponse.getIssuer(), idpRequestId);

		// bailout cases, update in case of SSO
		idpStateData.setRequestBinding(responseData.getBinding());

		// handle an error display with continue to RP
		if (cpResponse.showErrorPage()) {
			return preserveStateAndGetRedirectUriForAbortedResponse(cpResponse, idpStateData);
		}

		// audit incoming (to have a consistent conversationId we need the state, if gone we loose the correlation)
		auditResponseFromCp(httpServletRequest, responseData.getResponse(), cpResponse, idpStateData);

		// clone status from original response (a SAML object cannot be assigned to another parent)
		var authnResponse = createSamlResponseFromState(idpStateData, cpResponse);
		SamlValidationUtil.validateResponse(responseData);

		if (cpResponse.isAborted()) {
			setAbortedResponseStatus(cpResponse, authnResponse);
		}
		else {
			// propagated or overwritten status
			var response = responseData.getResponse();
			var statusMessage = OpenSamlUtil.getStatusMessage(response);
			var statusCode = OpenSamlUtil.getStatusCode(response);
			var nestedStatus = OpenSamlUtil.getNestedStatusCode(response);
			authnResponse.setStatus(SamlFactory.createResponseStatus(statusCode, statusMessage, nestedStatus));
		}

		// sign message
		var relyingParty = getRelyingParty(idpStateData);
		var claimsParty = getClaimsParty(cpResponse);
		prepareResponseToRp(authnResponse,
				relyingParty,
				trustBrokerProperties.getSkinnyAssertionNamespaces(),
				signFailureResponse(relyingParty));

		// send and audit
		establishSsoOrInvalidateState(relyingParty, claimsParty, idpStateData, false);
		var encodingParameters = buildEncodingParameters(relyingParty, idpStateData, responseData.getBinding());
		var resultResponseData = ResponseData.of(authnResponse, null, null);
		sendResponseToRp(resultResponseData, cpResponse, Optional.of(idpStateData),
				httpServletRequest, httpServletResponse, null, encodingParameters, outputService);

		// federation done, drop state
		stateCacheService.invalidate(idpStateData, this.getClass().getSimpleName());

		return null; // no redirects
	}

	private String preserveStateAndGetRedirectUriForAbortedResponse(CpResponse cpResponse, StateData idpStateData) {
		if (idpStateData.isExpired()) {
			log.debug("Preserving expired sessionId={} for support info fetching", idpStateData.getId());
			idpStateData.reInit();
		}
		stateCacheService.save(idpStateData, this.getClass().getSimpleName());
		String redirectUri;
		if (cpResponse.doAppRedirect()) {
			redirectUri = cpResponse.getFlowPolicy().getAppRedirectUrl();
		}
		else {
			redirectUri = apiSupport.getErrorPageUrlWithFlags(cpResponse.uiErrorCode(),
					TraceSupport.getOwnTraceParent(), idpStateData.getId(), cpResponse.uiFlags());
		}
		if (log.isDebugEnabled()) {
			log.debug(
					"Response to cpRequestId={} in sessionId={} aborted with statusCode={} statusMessage={} nestedStatusCode={}"
							+ " redirecting to redirectUri={}",
					cpResponse.getInResponseTo(), idpStateData.getId(), cpResponse.getStatusCode(),
					cpResponse.statusMessage(trustBrokerProperties.getSaml()),
					cpResponse.nestedStatusCode(trustBrokerProperties.getSaml()), redirectUri);
		}
		return redirectUri;
	}

	public String sendAbortedSamlResponseToRp(
			OutputService outputService, StateData stateData, HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, ResponseStatus responseStatus,
			SamlBinding samlBinding) {
		// handle an error display with continue to RP
		if (responseStatus.showErrorPage()) {
			return preserveStateAndGetRedirectUriForAbortedResponse(stateData.getCpResponse(), stateData);
		}

		// responder directly triggering on AuthnRequest
		var authnResponse = createSamlResponseFromState(stateData, null);
		setAbortedResponseStatus(responseStatus, authnResponse);

		// sign message
		var relyingParty = getRelyingParty(stateData);
		prepareResponseToRp(authnResponse,
				relyingParty,
				trustBrokerProperties.getSkinnyAssertionNamespaces(),
				signFailureResponse(relyingParty));

		// send and audit
		invalidateStateData(stateData, false);
		var encodingParameters = buildEncodingParameters(relyingParty, stateData, samlBinding);
		var resultResponseData = ResponseData.of(authnResponse, null, null);
		sendResponseToRp(resultResponseData, null, Optional.of(stateData),
				httpServletRequest, httpServletResponse, null, encodingParameters, outputService);

		return null; // no redirects
	}

	private void setAbortedResponseStatus(ResponseStatus responseStatus, Response authnResponse) {
		// script hook has overwritten the status
		var statusCode = responseStatus.getStatusCode();
		var nestedStatusCode = responseStatus.nestedStatusCode(trustBrokerProperties.getSaml());
		var statusMessage = responseStatus.statusMessage(trustBrokerProperties.getSaml());
		if (log.isDebugEnabled()) {
			log.debug("SAML exchange aborted by scripts signaling statusCode={} statusNestedCode={} statusMessage='{}' "
							+ "flowPolicy={}",
					statusCode, nestedStatusCode, statusMessage, responseStatus.getFlowPolicy());
		}
		authnResponse.setStatus(SamlFactory.createResponseStatus(statusCode, statusMessage, nestedStatusCode));
	}

	private static void prepareResponseToRp(StatusResponseType response, RelyingParty relyingParty,
			String skinnyAssertionNamespaces, boolean sign) {
		if (sign) {
			log.debug("Sending signed SAML response id={} towards RP rpIssuerId={}", response.getID(), relyingParty.getId());
			var signatureParameters = relyingParty.getSignatureParametersBuilder()
												  .skinnyAssertionNamespaces(skinnyAssertionNamespaces)
												  .build();
			SamlFactory.signSignableObject(response, signatureParameters);
		}
		else {
			log.info("Sending unsigned SAML response id={} towards RP rpIssuerId={}", response.getID(), relyingParty.getId());
			var signatureAlgos = relyingParty.getSignature();
			SamlUtil.prepareSamlObject(response,
					signatureAlgos != null ? signatureAlgos.getCanonicalizationAlgorithm() : null,
					null, skinnyAssertionNamespaces);
		}
	}

	@SuppressWarnings("java:S107") // internal method - depends on methods that require a lot of parameters
	private void sendResponseToRp(ResponseData<?> responseData, CpResponse cpResponse,
			Optional<StateData> idpStateData, HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, Credential credential, EncodingParameters encodingParameters,
			OutputService outputService) {
		addSsoCookies(idpStateData, httpServletResponse);
		sendResponse(responseData, cpResponse, idpStateData, httpServletRequest, httpServletResponse,
				credential, encodingParameters, outputService);
	}

	private void addSsoCookies(Optional<StateData> idpStateData, HttpServletResponse httpServletResponse) {
		if (idpStateData.isPresent()) {
			var stateData = idpStateData.get();
			if (stateData.isSsoEstablished()) {
				// SSO cookie for established session
				var cookie = ssoService.generateCookie(stateData);
				httpServletResponse.addCookie(cookie);
			}
		}
	}

	@SuppressWarnings("java:S107") // internal method - depends on methods that require a lot of parameters
	private void sendResponse(ResponseData<?> responseData, CpResponse cpResponse,
			Optional<StateData> idpStateData, HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, Credential credential, EncodingParameters encodingParameters,
			OutputService outputService) {
		// wrap response and handle relay state
		var response = responseData.getResponse();
		var destinationUrl = getDestination(response, idpStateData, cpResponse);
		var relayState = getRelayState(idpStateData, responseData.getRelayState());

		// emit
		outputService.sendResponse(response, credential, relayState, destinationUrl, httpServletResponse,
				encodingParameters, DestinationType.RP);

		// audit
		if (response instanceof Response) {
			auditResponseToRp(httpServletRequest, response, cpResponse, idpStateData.orElse(null));
		}

		txDelay();
	}

	// testing only
	private void txDelay() {
		var txDelay = trustBrokerProperties.getStateCache() == null ? 0 :
				trustBrokerProperties.getStateCache().getTxCommitDelay();
		if (txDelay > 0) {
			log.error("Delaying stateCache TX commit for {}ms to test race-conditions", txDelay);
			ProcessUtil.sleep(txDelay);
		}
	}

	private static String getRelayState(Optional<StateData> idpStateData, String requestRelayState) {
		var relayState = requestRelayState;
		if (relayState == null && idpStateData.isPresent()) {
			relayState = idpStateData.get().getSpStateData().getRelayState();
		}
		return relayState;
	}

	// pre-establish SSO before message generation
	private void adjustSsoSessionIdForRpResponse(RelyingParty relyingParty, StateData idpStateData, CpResponse cpResponse) {
		if (ssoService.isRelyingPartyOkForSso(relyingParty, idpStateData)) {
			idpStateData.setSsoSessionId(SsoSessionIdPolicy.generateSsoId(true, trustBrokerProperties.getSsoSessionIdPolicy()));
			adjustSsoSessionIdProperty(idpStateData, cpResponse);
		}
	}

	// post-establish SSO after message generation
	private void establishSsoOrInvalidateState(RelyingParty relyingParty, ClaimsParty claimsParty, StateData idpStateData,
			boolean success) {
		if (success && ssoService.isRelyingPartyOkForSso(relyingParty, idpStateData)) {
			var ssoGroupName = relyingParty.getSso().getGroupName();
			var ssoGroup = relyingPartySetupService.getSsoGroupConfig(ssoGroupName);
			ssoService.establishSso(relyingParty, claimsParty, idpStateData, ssoGroup);
		}
		invalidateStateData(idpStateData, success);
	}

	private void invalidateStateData(StateData idpStateData, boolean success) {
		if (!idpStateData.isSsoEstablished()) {
			stateCacheService.invalidate(idpStateData, success, this.getClass().getSimpleName());
		}
	}

	private RelyingParty getRelyingParty(StateData idpStateData) {
		var requestIssuer = idpStateData.getRpIssuer();
		var requestReferer = idpStateData.getRpReferer();
		return relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(requestIssuer, requestReferer);
	}

	private ClaimsParty getClaimsParty(CpResponse cpResponse) {
		var cpIssuerId = cpResponse.getIssuer();
		return relyingPartySetupService.getClaimsProviderSetupByIssuerId(cpIssuerId, null);
	}

	// Check if the rpIssuer matches the one for the ssoStateData CP response.
	// If stateDataByAuthnReq is null, relyingParty.id is used for the check.
	// Otherwise, stateDataByAuthnReq is expected to match relyingParty.
	private void refreshUserDataIfNeeded(StateData ssoStateData, StateData stateDataByAuthnReq, RelyingParty relyingParty) {
		var cpResponse = ssoStateData.getCpResponse();
		var authnIssuerId = stateDataByAuthnReq != null ? stateDataByAuthnReq.getRpIssuer() : relyingParty.getId();
		var stateToUpdate = getStateToUpdateFromIdm(ssoStateData, stateDataByAuthnReq);
		// if tenant matches we can continue with the state data
		// NOTE: We could do a freshness check here in case the state data is older than X because of changes in IDM => LATER
		var originalParticipantId = cpResponse.getRpIssuer();
		var newParticipant = !authnIssuerId.equals(originalParticipantId);
		var ssoForceIdmRefresh = relyingParty.isSsoEnabled() && Boolean.TRUE.equals(relyingParty.getSso().getForceIdmRefresh());
		if (!newParticipant && !ssoForceIdmRefresh) {
			log.info("Skip refreshing user data because IDP response already initiated by rpIssuer={} for configRpId={} "
					+ "(without SSO or forceIdmRefresh=true)", originalParticipantId, relyingParty.getId());
			resetStaleProfileSelection(newParticipant, originalParticipantId, ssoStateData, cpResponse, relyingParty);
			return;
		}
		// update with tenant data of the joining SSO member
		log.debug("Refreshing user data because rpIssuer={} previousRpIssuer={} ssoForceIdmRefresh={} configRpId={}",
				authnIssuerId, originalParticipantId, ssoForceIdmRefresh, relyingParty.getId());
		fetchIdmData(cpResponse, stateToUpdate, relyingParty.getClientName(), false);
		if (stateDataByAuthnReq != null) {
			stateDataByAuthnReq.setCpResponse(cpResponse);
		}
		resetStaleProfileSelection(newParticipant, originalParticipantId, ssoStateData, cpResponse, relyingParty);
	}

	private static StateData getStateToUpdateFromIdm(StateData ssoStateData, StateData stateDataByAuthnReq) {
		return stateDataByAuthnReq != null ? stateDataByAuthnReq : ssoStateData;
	}

	public String sendAuthnResponseToRpFromState(OutputService outputService, HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, StateData ssoStateData,
			StateData stateDataByAuthnReq) {

		// accept input
		var cpResponse = ssoStateData.getCpResponse();
		var authnRequestID = stateDataByAuthnReq.getSpStateData().getId();
		SamlUtil.validateSessionId(authnRequestID, "AuthnRequestId used as SP state ID");

		// keep operating on stateDataByAuthnReq until profile selection has been decided
		var spIssuer = stateDataByAuthnReq.getRpIssuer();
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(spIssuer, null);

		// in any case we need the data related to the RP tenant calling us
		log.debug("Done SSO all-profiles for cpIssuer={} rpIssuer={} subjectNameId={} authnRequestID={}",
				cpResponse.getIssuer(), relyingParty.getId(), cpResponse.getNameId(), authnRequestID);
		refreshUserDataIfNeeded(ssoStateData, stateDataByAuthnReq, relyingParty);

		// handle multiple profiles if feature is enabled
		var profileSelectionData = ProfileSelectionData.builder()
		   		.profileSelectionProperties(relyingParty.getProfileSelection())
				.selectedProfileId(ssoStateData.getSelectedProfileExtId())
				.exchangeId(stateDataByAuthnReq.getSpStateData().getRelayState())
				.applicationName(stateDataByAuthnReq.getRpApplicationName())
				.oidcClientId(stateDataByAuthnReq.getRpOidcClientId())
				.build();
		var psResult = profileSelectionService.doSsoProfileSelection(
				profileSelectionData, relyingParty, cpResponse, stateDataByAuthnReq);
		if (psResult.getSelectedProfileId() != null) {
			stateDataByAuthnReq.setSelectedProfileExtId(psResult.getSelectedProfileId());
		}

		if (psResult.getRedirectUrl() != null) {
			// SSO state CpResponse
			stateDataByAuthnReq.setCpResponse(cpResponse);
			stateCacheService.save(stateDataByAuthnReq, this.getClass().getSimpleName());
			return psResult.getRedirectUrl();
		}

		// ready to join SSO session
		ssoService.completeDeviceInfoPreservingStateForSso(ssoStateData, stateDataByAuthnReq, relyingParty);

		// send out audited response
		var authnResponse = createSignedSamlResponse(cpResponse, ssoStateData, psResult);

		// handle an error display with continue to RP (script hook result)
		if (authnResponse == null) {
			return preserveStateAndGetRedirectUriForAbortedResponse(cpResponse, ssoStateData);
		}

		var encodingParameters = buildEncodingParameters(relyingParty, ssoStateData, null);
		var responseData = ResponseData.of(authnResponse, null, null);
		sendResponse(responseData, cpResponse, Optional.of(ssoStateData), httpServletRequest, httpServletResponse,
				null, encodingParameters, outputService);

		return null;
	}

	// internal

	private void fetchIdmData(CpResponse cpResponse, StateData stateData, String clientName, boolean audited) {
		log.debug("Fetch IDM data for stateData={} cpResponse.issuer='{}' cpResponse.rpIssuer='{}' clientName='{}' audited={}",
				stateData.getId(), cpResponse.getIssuer(), cpResponse.getRpIssuer(), clientName, audited);

		var spStateData = stateData.getSpStateData();

		// IDM data
		var requestIssuer = spStateData.getIssuer();
		var requestReferer = spStateData.getReferer();

		// make sure CpResponse is clean for reuse
		updateCpResponseForSso(cpResponse, spStateData, clientName);

		// retrieve current attributes from IDM services
		getAttributesFromIdm(cpResponse, requestIssuer, audited);

		// derived attributes
		setProperties(cpResponse);

		// scripts (just before feature processing)
		scriptService.processCpAfterIdm(cpResponse, null, cpResponse.getIssuer(), null);
		scriptService.processRpAfterIdm(cpResponse, null, requestIssuer, requestReferer);

		// filter properties
		filterPropertiesSelection(cpResponse, requestIssuer, requestReferer);
	}

	// if null is returned, show error page according to cpResponse flow policy
	private Response createSignedSamlResponse(CpResponse cpResponse, StateData stateData, ProfileSelectionResult psResult) {
		var spStateData = stateData.getSpStateData();
		var requestIssuer = spStateData.getIssuer();
		var requestReferer = spStateData.getReferer();
		var relyingParty = getRelyingParty(stateData);
		var responseParameterBuilder = ResponseParameters.builder()
												   .rpIssuerId(requestIssuer)
												   .nameIdQualifier(null)
												   .setSessionIndex(true)
												   .rpReferer(requestReferer);
		if (stateData.isSsoEstablished()) {
			responseParameterBuilder.sessionIndex(stateData.getSsoSessionId());
			if (stateData.getExpirationTimestamp() != null) {
				var latestSessionEndTime = stateData.getLatestSsoSessionEndTime(trustBrokerProperties.getSsoSessionLifetimeSec());
				responseParameterBuilder.sessionNotOnOrAfter(latestSessionEndTime);
			}
			else {
				// calculated in StateCacheService on saving, should not happen at this stage
				log.info("Missing ExpirationTimestamp on SSO sessionId={}", stateData.getId());
			}
		}
		var responseParameters = responseParameterBuilder.build();
		var destination = ResponseFactory.getRpDestination(stateData, cpResponse);

		// Adjust final settings
		adjustSsoSessionIdProperty(stateData, cpResponse);

		// Avoid State.cpResponse modification
		var cpResponseClone = SerializationUtils.clone(cpResponse);

		// Assert profile selection filtering/mapping
		claimsMapperService.applyProfileSelection(cpResponseClone, psResult);

		// Apply subject name mapping
		SubjectNameMapper.adjustSubjectNameId(cpResponseClone, relyingParty);

		// Response changes with access to all data (including originalNameId)
		processBeforeResponseScript(cpResponseClone, requestIssuer, requestReferer);

		// Apply final filters (filtering, mapping, de-duplication, ...)
		claimsMapperService.applyFinalAttributeMapping(cpResponseClone, responseParameters, destination, relyingParty);

		// Final response changes, but only access to processed data (filtered and mapped)
		processOnResponseScript(cpResponseClone, requestIssuer, requestReferer);

		// Retain context information set by script
		cpResponse.setRpContext(cpResponseClone.getRpContext());

		// script triggered abort, retain abort information
		if (cpResponseClone.showErrorPage()) {
			cpResponse.copyAbortConditions(cpResponseClone);
			return null;
		}

		// assemble and sign
		var authnResponse = createSamlResponseFromState(stateData, cpResponseClone);

		// Determine response status
		if (cpResponseClone.isAborted()) {
			setAbortedResponseStatus(cpResponseClone, authnResponse);
		}
		else {
			authnResponse.setStatus(SamlFactory.createResponseStatus(StatusCode.SUCCESS));
			var assertion = responseFactory.createAssertion(stateData, cpResponseClone, responseParameters);

			// Retain results list for auditing only
			cpResponse.setResults(cpResponseClone.getResults());

			// Add and encrypt assertion (if necessary)
			addAssertionToResponse(authnResponse, assertion, relyingParty);
		}

		// sign message as well
		prepareResponseToRp(authnResponse, relyingParty,
				trustBrokerProperties.getSkinnyAssertionNamespaces(),
				signSuccessResponse(relyingParty));
		return authnResponse;
	}

	private void processBeforeResponseScript(CpResponse cpResponse, String requestIssuer, String requestReferer) {
		if (cpResponse != null) {
			scriptService.processCpBeforeResponse(cpResponse, null, cpResponse.getIssuer(), null);
			scriptService.processRpBeforeResponse(cpResponse, null, requestIssuer, requestReferer);
		}
	}

	private void processOnResponseScript(CpResponse cpResponse, String requestIssuer, String requestReferer) {
		if (cpResponse != null) {
			scriptService.processCpOnResponse(cpResponse, null, cpResponse.getIssuer(), null);
			scriptService.processRpOnResponse(cpResponse, null, requestIssuer, requestReferer);
		}
	}

	boolean signSuccessResponse(RelyingParty relyingParty) {
		return relyingParty.requireSignedResponse(trustBrokerProperties.getSecurity().isDoSignSuccessResponse());
	}

	boolean signFailureResponse(RelyingParty relyingParty) {
		return relyingParty.requireSignedResponse(trustBrokerProperties.getSecurity().isDoSignFailureResponse());
	}

	void addAssertionToResponse(Response authnResponse, Assertion assertion, RelyingParty relyingParty) {
		var rpId = relyingParty.getId();

		Encryption encryption = relyingParty.getEncryption();
		var kea = getKeyEncryptionAlgorithm(encryption);
		var dea = getDataEncryptionAlgorithm(encryption);

		Credential encryptionCred = relyingParty.getRpEncryptionTrustCredential();

		// If destination is XTB -> encryption for OIDC
		boolean isXtbDestination = HrdSupport.isXtbDestination(trustBrokerProperties, authnResponse.getDestination());
		if (isXtbDestination) {
			encryptionCred = relyingParty.getRpSigner();
		}

		if (assertionEncryptionReq(encryptionCred, isXtbDestination, rpId)) {
			var keyPlacement = getKeyPlacement(encryption, rpId);
			var emitSki = emitSki(encryption, rpId);
			var encryptedAssertion = EncryptionUtil.encryptAssertion(assertion,
					encryptionCred, dea, kea, keyPlacement, rpId, emitSki);
			authnResponse.getEncryptedAssertions().add(encryptedAssertion);
			log.debug("Assertion for rp={} encrypted with cred={}, DataEncryptionAlg={} KeyEncryptionAlg={}", rpId,
					encryptionCred.getEntityId(), dea, kea);
			return;
		}

		authnResponse.getAssertions().add(assertion);
	}

	boolean assertionEncryptionReq(Credential encryptionCred, boolean isXtbDestination, String rpId) {

		if (encryptionCred == null) {
			log.debug("No EncryptionKeystore on={}, assertion encryption will be skipped", rpId);
			return false;
		}

		if (isXtbDestination) {
			boolean samlEncrypt = trustBrokerProperties.getOidc().isSamlEncrypt();
			log.debug("Encrypt Assertion for OIDC id={} enabled={}", rpId, samlEncrypt);
			return samlEncrypt;
		}

		return true;
	}


	public static String getDataEncryptionAlgorithm(Encryption encryption) {
		if (encryption == null || encryption.getDataEncryptionAlgorithm() == null) {
			return EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256;
		}
		return encryption.getDataEncryptionAlgorithm();
	}

	public static String getKeyEncryptionAlgorithm(Encryption encryption) {
		if (encryption == null || encryption.getKeyEncryptionAlgorithm() == null) {
			return EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP;
		}
		return encryption.getKeyEncryptionAlgorithm();
	}

	private static Encrypter.KeyPlacement getKeyPlacement(Encryption encryption, String requestIssuer) {
		if (encryption != null && encryption.getKeyPlacement() != null) {
			return switch (encryption.getKeyPlacement()) {
				case PEER -> Encrypter.KeyPlacement.PEER;
				case INLINE -> Encrypter.KeyPlacement.INLINE;
			};
		}
		log.debug("Missing KeyPlacement config for rpIssuerId={}, falling back to {}",
				requestIssuer, EncryptionKeyPlacement.PEER);
		return Encrypter.KeyPlacement.PEER;
	}

	private static boolean emitSki(Encryption encryption, String requestIssuer) {
		if (encryption != null && encryption.getKeyInfo() != null) {
			return encryption.getKeyInfo() == EncryptionKeyInfo.SKI;
		}
		log.debug("Missing KeyInfo config for rpIssuerId={}, falling back to {}",
				requestIssuer, EncryptionKeyInfo.CERTIFICATE);
		return false;
	}

	public void handleLogoutRequest(OutputService outputService, LogoutRequest logoutRequest, String requestRelayState,
			HttpServletRequest request, HttpServletResponse response, SignatureContext signatureContext) {
		var issuer = logoutRequest.getIssuer().getValue();
		var requestReferrer = WebUtil.getReferer(request);
		var relyingParties = ssoService.getRelyingPartiesForSamlSlo(issuer, requestReferrer);
		validateLogoutRequest(logoutRequest, signatureContext, relyingParties);
		var logoutParams = LogoutParams.of(request, response, logoutRequest, requestRelayState, requestReferrer,
				signatureContext, outputService);
		var logoutState = SsoService.SloState.builder().build();
		for (var relyingParty : relyingParties) {
			logoutRelyingParty(relyingParty, requestReferrer, logoutParams, logoutState);
		}
	}

	private void logoutRelyingParty(RelyingParty relyingParty, String referer, LogoutParams logoutParams,
			SsoService.SloState sloState) {
		var stateData = ssoService.logoutRelyingParty(logoutParams.logoutRequest.getIssuer().getValue(),
				mapSessionIndexes(logoutParams.logoutRequest.getSessionIndexes()),
				relyingParty, logoutParams.request.getCookies(), sloState);

		// we audit for every cookie we kill
		ssoService.auditLogoutRequestFromRp(
				logoutParams.request, logoutParams.logoutRequest, stateData.orElse(null), relyingParty, null);

		// we send a SAML POST LogoutResponse only once
		// referrer matches are processed first, hence we send the response based on the referrer if we find a match for that
		if (!sloState.isResponseSent()) {
			var encodingParameters = buildEncodingParameters(relyingParty, null, logoutParams.signatureContext.getBinding());
			WebUtil.addCookies(logoutParams.response, sloState.getCookiesToExpire());

			sendLogoutResponse(logoutParams, sloState, stateData, relyingParty,
					referer, encodingParameters);
			sloState.setResponseSent(true);
		}
	}

	@SuppressWarnings("java:S1168")
	private static List<String> mapSessionIndexes(List<SessionIndex> sessionIndices) {
		if (sessionIndices == null) {
			return null;
		}
		return sessionIndices.stream().map(SessionIndex::getValue).toList();
	}

	private void validateLogoutRequest(LogoutRequest logoutRequest, SignatureContext signatureContext,
			List<RelyingParty> relyingParties) {
		if (!relyingParties.isEmpty()) {
			// The check is based on the first RP (based on the issuer, if found), we use that one for the LogoutResponse
			// This check needs to be performed before sending the response in the loop.
			// use the same flags as for AuthnRequest to control if request and signature validation is required or optional
			if (trustBrokerProperties.getSecurity().isValidateAuthnRequest()) {
				// use the RP to which we send the LogoutResponse below - SLO matches referrer before issuer
				var signingRp = relyingParties.get(0);
				log.debug("Relying party for LogoutRequest signature verification is id={}", signingRp.getId());
				validateBinding(signingRp, signatureContext.getBinding());
				signatureContext.setRequireSignature(signingRp.requireSignedLogoutRequest());
				AssertionValidator.validateRequestSignature(logoutRequest, signingRp.getRpTrustCredentials(),
						trustBrokerProperties,
						signatureContext);
			}
			else {
				log.error("trustbroker.config.security.validateAuthnRequest=false: Security on LogoutRequest disabled!!!");
			}
		}
	}

	private static void validateBinding(RelyingParty relyingParty, SamlBinding binding) {
		if (!relyingParty.isValidInboundBinding(binding)) {
			throw new RequestDeniedException(String.format("Relying party rpIssuerId=%s does not support inbound binding=%s",
					relyingParty.getId(), binding));
		}
	}

	private void sendLogoutResponse(LogoutParams logoutParams, SsoService.SloState sloState, Optional<StateData> stateData,
			RelyingParty relyingParty, String referer, EncodingParameters encodingParameters) {
		var nameId = getNameIdFromSessionOrLogoutRequest(stateData, logoutParams.logoutRequest);
		var params = ssoService.buildSloResponseParameters(relyingParty, referer, sloState.getSloNotifications(), nameId,
				null, null);
		encodingParameters.setUseRedirectBinding(params.useHttpGet());
		encodingParameters.setTemplateParameters(params.velocityParameters());
		var sloUrl = ssoService.computeSamlSingleLogoutUrl(logoutParams.requestReferrer, relyingParty);
		var issuer = relyingParty.getSloIssuer(SloProtocol.SAML2).orElse(null);
		var logoutResponse = createLogoutResponse(logoutParams.logoutRequest, sloUrl, issuer);
		logoutResponse.setStatus(SamlFactory.createResponseStatus(StatusCode.SUCCESS));
		// sign message as well - for redirect binding the signature is part of the query, not on the object
		var sign = signSuccessResponse(relyingParty);
		prepareResponseToRp(logoutResponse, relyingParty,
				trustBrokerProperties.getSkinnyAssertionNamespaces(),
				sign && !params.useHttpGet());
		Credential credential = null;
		if (sign && params.useHttpGet()) {
			var signatureParameters = relyingParty.getSignatureParametersBuilder().build();
			credential = signatureParameters.getCredential();
			encodingParameters.setSignatureAlgorithm(signatureParameters.getSignatureAlgorithm());
		}
		// NameID for SAML notifications
		var responseData = ResponseData.of(logoutResponse, logoutParams.requestRelayState, null);
		sendResponseToRp(responseData, null, stateData, logoutParams.request, logoutParams.response,
				credential, encodingParameters, logoutParams.outputService);
	}

	private static NameID getNameIdFromSessionOrLogoutRequest(Optional<StateData> stateData, LogoutRequest logoutRequest) {
		NameID nameId = null;
		if (stateData.isPresent()) {
			nameId = ResponseFactory.createNameId(stateData.get().getCpResponse());
			if (nameId != null) {
				log.debug("SLO notification NameId={} from session with id={}", nameId, stateData.get().getId());
			}
		}
		if (nameId == null) {
			nameId = logoutRequest.getNameID();
			log.info("No session, using SLO notification nameId={} from LogoutRequest with id={}",
					nameId != null ? nameId.getValue() : "", logoutRequest.getID());
			// this way an attacker could trigger a logout for someone else (with an unsigned LogoutRequest)
			// as the logout should only affect state associated with the requesting browser, this is not a problem
		}
		return nameId;
	}

	private static EncodingParameters buildEncodingParameters(RelyingParty relyingParty, StateData idpStateData,
			SamlBinding inboundSamlBinding) {
		var useArtifactBinding = useArtifactBinding(relyingParty, idpStateData, inboundSamlBinding);
		var useSoapBinding = inboundSamlBinding == SamlBinding.SOAP;
		return EncodingParameters.builder()
								 .useArtifactBinding(useArtifactBinding)
								 .useSoapBinding(useSoapBinding)
								 .build();
	}

	private Response createSamlResponseFromState(StateData idpStateData, CpResponse cpResponse) {
		var response = SamlFactory.createResponse(Response.class, trustBrokerProperties.getIssuer());
		response.setDestination(ResponseFactory.getRpDestination(idpStateData, cpResponse));
		response.setInResponseTo(idpStateData.getSpStateData().getId());
		return response;
	}

	private StatusResponseType createLogoutResponse(LogoutRequest logoutRequest, String requestReferrer, String issuer) {
		var response = SamlFactory.createResponse(LogoutResponse.class, ssoService.getSloIssuerWithFallback(issuer));
		// we don't know a consumer URL in the config or the LogoutRequest - send it back to the referrer
		response.setDestination(requestReferrer);
		response.setInResponseTo(logoutRequest.getID());
		return response;
	}

	private static <T extends StatusResponseType> String getDestination(T response,
			Optional<StateData> idpStateData, CpResponse cpResponse) {
		String consumerUrl;
		if (response instanceof LogoutResponse) {
			consumerUrl = response.getDestination();
		}
		else {
			if (idpStateData.isEmpty()) {
				throw new TechnicalException(String.format("Missing IDP state for response type %s",
						response.getClass().getName()));
			}
			var stateData = idpStateData.get();
			consumerUrl = ResponseFactory.getRpDestination(stateData, cpResponse);
		}
		log.debug("Set SAML POST target from AuthnRequest AssertionConsumerServiceUrl={}", consumerUrl);
		return consumerUrl;
	}

	private void auditResponseToRp(HttpServletRequest httpServletRequest,
			StatusResponseType response, CpResponse cpResponse, StateData stateData) {
		var relyingParty = stateData != null ?
				relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(stateData.getRpIssuer(), null, true)
				: null;
		var auditDto = new OutboundAuditMapper(trustBrokerProperties)
				.mapFrom(stateData)
				.mapFrom(cpResponse)
				.mapFrom(response)
				.mapFrom(httpServletRequest)
				.mapFrom(relyingParty)
				.build();
		auditDto.setSide(DestinationType.RP.getLabel());
		auditService.logOutboundFlow(auditDto);
	}

	private void auditResponseFromCp(HttpServletRequest httpServletRequest,
			StatusResponseType response, CpResponse cpResponse, StateData stateData) {
		var relyingParty = stateData != null ?
				relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(stateData.getRpIssuer(), null, true)
				: null;
		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(stateData)
				.mapFrom(cpResponse)
				.mapFrom(response)
				.mapFrom(httpServletRequest)
				.mapFrom(relyingParty)
				.build();
		auditDto.setSide(DestinationType.CP.getLabel());
		auditService.logInboundFlow(auditDto);
	}

	// Handling interactive profile selection from UI with data from the session
	public String sendResponseWithSelectedProfile(OutputService outputService, ProfileRequest profileRequest,
			HttpServletRequest request, HttpServletResponse response) {
		// input
		var profileRequestId = profileRequest.getStateId();
		SamlValidationUtil.validateProfileRequestId(profileRequestId);

		// state from interactive profile selection handling
		var stateData = stateCacheService.find(profileRequestId, this.getClass().getSimpleName());

		// selected profile from user via UI
		stateData.setSelectedProfileExtId(profileRequest.getProfileId());

		var incomingDeviceId = WebSupport.getDeviceId(request);

		// handle SAML response from state
		ResponseData<Response> responseData = ResponseData.of(null, profileRequestId, null);
		return sendSuccessSamlResponseToRp(outputService, responseData, stateData, incomingDeviceId, request, response);
	}

	public String sendResponseToRpFromSessionState(OutputService outputService, RelyingParty relyingParty, StateData idpStateData,
			HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
		var cpResponse = idpStateData.getCpResponse();

		// handle multiple profiles if feature is enabled
		var profileSelectionData = ProfileSelectionData.builder()
													   .profileSelectionProperties(relyingParty.getProfileSelection())
													   .selectedProfileId(idpStateData.getSelectedProfileExtId())
													   .exchangeId(idpStateData.getSpStateData().getRelayState())
													   .applicationName(idpStateData.getApplicationName())
													   .oidcClientId(idpStateData.getRpOidcClientId())
													   .build();
		var psResult = profileSelectionService.doFinalProfileSelection(
				profileSelectionData, relyingParty, cpResponse, idpStateData);

		// now we can create the SAML response
		var samlResponse = createSignedSamlResponse(cpResponse, idpStateData, psResult);

		if (samlResponse == null) {
			return preserveStateAndGetRedirectUriForAbortedResponse(cpResponse, idpStateData);
		}

		// check SSO after the AR and IDM update
		var claimsParty = getClaimsParty(cpResponse);
		establishSsoOrInvalidateState(relyingParty, claimsParty, idpStateData, !cpResponse.isAborted());

		var encodingParameters = buildEncodingParameters(relyingParty, idpStateData, null);

		log.debug("Response sent for cpIssuer={} rpIssuer={} subjectNameId={} aborted={}",
				cpResponse.getIssuer(), relyingParty.getId(), cpResponse.getNameId(), cpResponse.isAborted());
		var responseData = ResponseData.of(samlResponse, null, null);
		sendResponseToRp(responseData, cpResponse, Optional.of(idpStateData), httpServletRequest, httpServletResponse,
				null, encodingParameters, outputService);
		return null;
	}

	public void reloadIdmData(RelyingParty relyingParty, StateData idpStateData) {
		// re-fetch IDM data, usually after access request
		var cpResponse = idpStateData.getCpResponse();
		fetchIdmData(cpResponse, idpStateData, relyingParty.getClientName(), true);
	}

	// works for SAML messages created by XTB
	public String findRelyingPartyIdForTrustbrokerSamlObject(SAMLObject samlObject) {
		Optional<StateData> stateData = Optional.empty();
		if (samlObject instanceof StatusResponseType response) {
			var authnRequestId = response.getInResponseTo();
			stateData = stateCacheService.findBySpId(authnRequestId, this.getClass().getSimpleName());
		}
		else if (samlObject instanceof RequestAbstractType request) {
			var sessionId = request.getID();
			stateData = stateCacheService.findValidState(sessionId, this.getClass().getSimpleName());
		}
		if (stateData.isPresent()) {
			var rpIssuerId = stateData.get().getRpIssuer();
			log.debug("Found rpIssuerId={} from sessionId={}", rpIssuerId, stateData.get().getId());
			return rpIssuerId;
		}
		return null;
	}

}
