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

package swiss.trustbroker.homerealmdiscovery.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.TreeSet;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.X509Credential;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.idm.dto.IdmRequests;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.ArtifactBinding;
import swiss.trustbroker.federation.xmlconfig.AuthorizedApplication;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderMappings;
import swiss.trustbroker.federation.xmlconfig.CounterParty;
import swiss.trustbroker.federation.xmlconfig.HomeName;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.SsoGroup;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartyUtil;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.util.PropertyUtil;

@Service
@AllArgsConstructor
@Slf4j
public class RelyingPartySetupService {

	private final RelyingPartyDefinitions relyingPartiesMapping;

	private final TrustBrokerProperties trustBrokerProperties;

	private final List<IdmQueryService> idmQueryServices;

	public RelyingParty getRelyingPartyByIssuerIdOrReferrer(String issuerId, String refererUrl, boolean tryOnly) {
		var relyingParty = getRelyingPartyById(issuerId);
		if (relyingParty.isEmpty()) {
			log.debug("Could not locate RP setup using issuerId={} falling back to referer={} instead", issuerId, refererUrl);
			relyingParty = getRelyingPartyByReferrer(refererUrl);
		}
		if (relyingParty.isEmpty() && !tryOnly) {
			// This can happen when XTB is addressed by an unknown RP or if the XML setup is inconsistent.
			// References are validated as part of the configuration startup, so check the startup logs.
			// Also note that in the single CP cases the mapping XML might also have a missing entry.
			throw new RequestDeniedException(String.format(
					"Check SetupRP.xml: There is no RelyingParty for RP issuer='%s' or referrer='%s' in rpIds='%s'",
					issuerId, refererUrl, getRelyingPartyIds()));
		}
		log.debug("Found RP by issuerId={} and referrerUrl={} relyingParty={}", issuerId, refererUrl,
				relyingParty.isPresent() ? relyingParty.get().getId() : null);
		return relyingParty.orElse(null);
	}

	private Optional<RelyingParty> getRelyingPartyByReferrer(String refererUrl) {
		List<RelyingParty> relyingParties = new ArrayList<>();
		getAllRelyingPartiesByReferer(relyingParties, refererUrl, true);
		if (!relyingParties.isEmpty()) {
			var relyingParty = Optional.of(relyingParties.get(0));
			if (relyingParties.size() > 1 && log.isDebugEnabled()) {
				log.debug("Found multiple RP setups using issuerId={} referrer={}: {}",
						relyingParty.get().getId(), refererUrl, CollectionUtil.toLogString(relyingParties));
			}
			return relyingParty;
		}
		return Optional.empty();
	}

	public Optional<Pair<RelyingParty, AuthorizedApplication>> getRelyingPartyByAuthorizedApplication(String application) {
		return relyingPartiesMapping.getRelyingPartyByAuthorizedApplication(application);
	}

	// returns all RPs matching the issuer, followed by the ones matching the referrer (exact match before near matches)
	// parameter order unchanged as we always have (issuer, referer)
	// issuer must be first because an integrator could copy an ACUrl or referrer into the wrong configuration
	// see exception in getRelyingPartyByIssuerIdOrReferrer
	public List<RelyingParty> getOrderedRelyingPartiesForSlo(String issuerId, String refererUrl) {
		List<RelyingParty> relyingParties = new ArrayList<>();

		getAllRelyingPartiesById(relyingParties, issuerId);
		var rpByIdCount = relyingParties.size();
		log.debug("Found rpCount={} for rpIssuer={}", rpByIdCount, issuerId);

		// Test data has localhost:7070 ACLs all over the place so for proper logout testing without a ton of misleading
		// audit entries we need to get rid of the referer matching the issuer match is working.
		// This code should be discarded anyway as the discontinued stealth mode is gone and is not even being used in there, actually.
		if (rpByIdCount == 0) {
			getAllRelyingPartiesByReferer(relyingParties, refererUrl, false);
			var rpByRefererCount = relyingParties.size() - rpByIdCount;
			log.info("Found rpIssuerCount={} for rpIssuer={} and rpIssuerCount2={} for referrer={}",
					rpByIdCount, issuerId, rpByRefererCount, refererUrl);
		}
		return relyingParties;
	}

	public RelyingParty getRelyingPartyByIssuerIdOrReferrer(String issuerId, String refererUrl) {
		return getRelyingPartyByIssuerIdOrReferrer(issuerId, refererUrl, false);
	}

	// hostname in referer to be found in acsUrl consumers whitelist
	private void getAllRelyingPartiesByReferer(List<RelyingParty> relyingParties, String refererUrl,
			boolean uniqueAcsUrl) {
		List<String> refererIds = RelyingPartyUtil.getIdsFromReferer(refererUrl);
		for (String refererId : refererIds) {
			addRelyingPartiesByRefererId(relyingParties, refererId, uniqueAcsUrl);
		}
		if (relyingParties.isEmpty() && log.isDebugEnabled()) {
			log.debug("Relying party to claims provider mapping via referer={} did not match anything using rpIds={}",
					refererUrl, String.join(",", refererIds));
		}
	}

	private void addRelyingPartiesByRefererId(List<RelyingParty> relyingParties, String refererId, boolean uniqueAcsUrl) {
		var relyingPartiesByAcsUrl = getRelyingPartiesByAcsUrlMatch(refererId);
		if (relyingPartiesByAcsUrl.isEmpty()) {
			var relyingParty = getRelyingPartyById(refererId);
			if (relyingParty.isPresent()) {
				addNonDuplicateRp(relyingParties, relyingParty.get(), refererId, "ID by referer");
			}
		}
		else if (uniqueAcsUrl) {
			addNonDuplicateRp(relyingParties, relyingPartiesByAcsUrl.get(0), refererId, "ACS URL by referer");
		}
		else {
			for (var relyingParty : relyingPartiesByAcsUrl) {
				addNonDuplicateRp(relyingParties, relyingParty, refererId, "ACS URL by referer");
			}
		}
	}

	private static void addNonDuplicateRp(List<RelyingParty> relyingParties, RelyingParty relyingParty, String matchId,
			String source) {
		if (!relyingParties.contains(relyingParty)) {
			log.debug("Found RP {} for {} matching {}", relyingParty.getId(), source, matchId);
			relyingParties.add(relyingParty);
		}
	}

	// hostname in referer used as an RP ID
	private Optional<RelyingParty> getRelyingPartyById(String id) {
		return relyingPartiesMapping.getRelyingPartySetup().getRelyingParties().stream().filter(
				relyingParty -> relyingParty.getId().equalsIgnoreCase(id)
		).findFirst();
	}

	public Optional<RelyingParty> getRelyingPartyByArtifactSourceIdOrReferrer(String sourceId, String refererUrl) {
		var relyingParty = getRelyingPartyByArtifactSourceId(sourceId);
		if (relyingParty.isEmpty()) {
			log.debug("No RP found for sourceId={} - fallback to refererUrl={}", sourceId, refererUrl);
			relyingParty = getRelyingPartyByReferrer(refererUrl);
		}
		return relyingParty;
	}

	private Optional<RelyingParty> getRelyingPartyByArtifactSourceId(String sourceId) {
		var relyingPartyOpt = relyingPartiesMapping.getRelyingPartySetup().getRelyingParties().stream().filter(
				relyingParty -> matchesSourceId(sourceId, relyingParty.getId(), relyingParty.getSamlArtifactBinding())
		).findFirst();
		if (relyingPartyOpt.isPresent()) {
			log.debug("Found rpIssuerId={} for sourceId={}", relyingPartyOpt.get().getId(), sourceId);
		}
		return relyingPartyOpt;
	}

	static boolean matchesSourceId(String sourceId, String issuerId, ArtifactBinding artifactBinding) {
		log.trace("Matching artifact sourceId={} against issuerId={} and artifactBinding={}",
				sourceId, issuerId, artifactBinding);
		if (artifactBinding != null) {
			if (artifactBinding.getSourceIdEncoded() != null && artifactBinding.getSourceIdEncoded().equals(sourceId)) {
				log.debug("sourceId={} matches ArtifactBinding sourceIdEncoded={} for issuerId={}",
						sourceId, artifactBinding.getSourceIdEncoded(), issuerId);
				return true;
			}
			if (artifactBinding.getSourceId() != null &&
					OpenSamlUtil.calculateArtifactSourceIdFromIssuerId(artifactBinding.getSourceId()).equals(sourceId)) {
				log.debug("sourceId={} matches ArtifactBinding sourceId={} for issuerId={}",
						sourceId, artifactBinding.getSourceId(), issuerId);
				return true;
			}
		}
		if (OpenSamlUtil.calculateArtifactSourceIdFromIssuerId(issuerId).equals(sourceId)) {
			log.debug("sourceId={} matches issuerId={}", sourceId, issuerId);
			return true;
		}
		return false;
	}

	public Optional<ClaimsParty> getClaimsProviderByArtifactSourceIdOrReferrer(String sourceId, String refererUrl) {
		var claimsParty = getClaimsProviderByArtifactSourceId(sourceId);
		if (claimsParty.isEmpty()) {
			log.debug("No CP found for sourceId={} - fallback to refererUrl={}", sourceId, refererUrl);
			claimsParty = getClaimsProviderSetupByReferer(refererUrl);
		}
		return claimsParty;
	}

	public Optional<ClaimsParty> getClaimsProviderByArtifactSourceId(String sourceId) {
		var claimsPartyOpt = relyingPartiesMapping.getClaimsProviderSetup().getClaimsParties().stream().filter(
				claimsParty -> matchesSourceId(sourceId, claimsParty.getId(), claimsParty.getSamlArtifactBinding())
		).findFirst();
		if (claimsPartyOpt.isPresent()) {
			log.debug("Found cpIssuerId={} for sourceId={}", claimsPartyOpt.get().getId(), sourceId);
		}
		return claimsPartyOpt;
	}

	private void addRelyingPartiesNearlyMatching(String id, List<RelyingParty> matchingRps) {
		if (!trustBrokerProperties.isPepIssuerMatchingEnabled(id)) {
			return;
		}
		for (var rp : relyingPartiesMapping.getRelyingPartySetup().getRelyingParties()) {
			for (var dropPattern : trustBrokerProperties.getSloIssuerIdDropPatterns()) {
				var truncatedId = rp.getId().replaceAll(dropPattern, "");
				if (id.equals(truncatedId)) {
					log.debug("Relying party '{}' matches truncated party: '{}'", id, truncatedId);
					addNonDuplicateRp(matchingRps, rp, truncatedId, "Truncated ID");
				}
			}
		}
	}

	// returns exact match before near match
	private void getAllRelyingPartiesById(List<RelyingParty> matchingRps, String id) {
		var exactMatch = getRelyingPartyById(id);
		if (exactMatch.isPresent()) {
			addNonDuplicateRp(matchingRps, exactMatch.get(), id, "ID");
		}
		else {
			addRelyingPartiesNearlyMatching(id, matchingRps);
		}
	}

	private static boolean acsUrlListContainsReferrer(RelyingParty relyingParty, String referrerId) {
		if (relyingParty == null || relyingParty.getAcWhitelist() == null) {
			return false;
		}
		return relyingParty.getAcWhitelist().findFirst(String::contains, referrerId).isPresent();
	}

	private List<RelyingParty> getRelyingPartiesByAcsUrlMatch(String refererId) {
		return relyingPartiesMapping.getRelyingPartySetup().getRelyingParties().stream().filter(
				relyingParty -> acsUrlListContainsReferrer(relyingParty, refererId)
		).toList();
	}

	public Optional<ClaimsParty> getClaimsProviderSetupByIssuerId(String id) {
		return relyingPartiesMapping.getClaimsProviderSetup().getClaimsParties().stream().filter(
				claimsParty -> claimsParty.getId().equalsIgnoreCase(id)
		).findFirst();
	}

	public List<ClaimsParty> getClaimsProviderSetupByResponseIssuerId(String id) {
		return relyingPartiesMapping.getClaimsProviderSetup().getClaimsParties().stream().filter(
				claimsParty -> claimsParty.getResponseIssuer().equalsIgnoreCase(id)
		).toList();
	}

	// debug only
	private String getRelyingPartyIds() {
		var sb = new StringBuilder("[");
		relyingPartiesMapping.getRelyingPartySetup().getRelyingParties().forEach(
				claimRuleDef -> {
					sb.append(claimRuleDef.getId());
					sb.append(",");
				}
		);
		sb.append("]");
		return sb.toString().replace(",]", "]");
	}

	private String getCpIds() {
		var sb = new StringBuilder("[");
		relyingPartiesMapping.getClaimsProviderSetup().getClaimsParties().forEach(
				claimsParty -> {
					sb.append(claimsParty.getId());
					sb.append(",");
				}
		);
		sb.append("]");
		return sb.toString().replace(",]", "]");
	}

	public ClaimsParty getClaimsProviderSetupByIssuerId(String issuerId, String refererUrl) {
		return getClaimsProviderSetupByIssuerId(issuerId, refererUrl, false);
	}

	private static SecurityPolicies getSecurityPolicies(CounterParty counterParty) {
		if (counterParty != null) {
			return counterParty.getSecurityPolicies();
		}
		return null;
	}

	public ClaimsParty getClaimsProviderSetupByIssuerId(String issuerId, String refererUrl, boolean tryOnly) {
		Optional<ClaimsParty> claimsParty = getClaimsProviderSetupByIssuerId(issuerId);
		if (claimsParty.isEmpty()) {
			log.debug("Could not find ClaimsParty by cpId={}, falling back to referer={} instead", issuerId, refererUrl);
			claimsParty = getClaimsProviderSetupByReferer(refererUrl);
		}
		if (claimsParty.isEmpty() && !tryOnly) {
			var msg = String.format(
					"Check SetupCP.xml: There is no ClaimsParty for cpId='%s' or referrer='%s' in cpIds='%s'",
					issuerId, refererUrl, getCpIds());
			throw new RequestDeniedException(msg);
		}
		log.debug("Found CP by issuerId={} and referrerUrl={}", issuerId, refererUrl);
		return claimsParty.orElse(null);
	}

	public String getHomeName(ClaimsParty claimsParty, List<Assertion> assertions, CpResponse cpResponseDTO) {
		OpenSamlUtil.checkAssertionsLimitations(assertions, Collections.emptyList(), "HomeRealm selection");

		var configHomeName = "";
		var messageHomeName = "";

		// Get homeName from configured HomeName reference, otherwise use configured constant value
		var homeName = claimsParty.getHomeName();
		if (homeName != null) {
			configHomeName = homeName.getName();
			messageHomeName = getHomeNameFromCpResponse(homeName, cpResponseDTO);
		}
		if (!configHomeName.isEmpty() && !messageHomeName.isEmpty() && !configHomeName.equals(messageHomeName)) {
			log.debug("CP Attribute='{}' with AttributeValue='{}' does not match SetupCP.ClaimsParty.HomeName='{}' "
					+ "Using {} from CP response", CoreAttributeName.HOME_NAME.getNamespaceUri(),
					messageHomeName, configHomeName, CoreAttributeName.HOME_NAME.getName());
		}

		return messageHomeName.isEmpty() ? configHomeName : messageHomeName;
	}

	private static String getHomeNameFromCpResponse(HomeName homeName, CpResponse cpResponse) {
		var messageHomeName = "";
		if (homeName.getReference() != null && cpResponse.getAttribute(homeName.getReference()) != null) {
			messageHomeName = cpResponse.getAttribute(homeName.getReference());
		}
		return messageHomeName;
	}

	private Optional<ClaimsParty> getClaimsProviderSetupByReferer(String refererUrl) {
		Optional<ClaimsParty> claimsParty = Optional.empty();
		List<String> refererIds = RelyingPartyUtil.getIdsFromReferer(refererUrl);
		for (String id : refererIds) {
			claimsParty = getClaimsProviderSetupByIssuerId(id);
			if (claimsParty.isPresent()) {
				break;
			}
		}
		if (claimsParty.isEmpty() && log.isDebugEnabled()) {
			log.debug("ClaimsParty via referer={} did not match anything using cpIds={}",
					refererUrl, String.join(",", refererIds));
		}
		return claimsParty;
	}

	public Optional<IdmLookup> getIdmLookUp(RelyingParty relyingParty) {
		var idmLookup = relyingParty.getIdmLookup();
		if (idmLookup == null) {
			log.info("RelyingParty id='{}' has no IDMLookup", relyingParty.getId());
		}
		return Optional.ofNullable(idmLookup);
	}

	public List<Credential> getAllCpDecryptionCredentials() {
		if (relyingPartiesMapping.getClaimsProviderSetup() == null) {
			log.warn("RelyingPartiesMapping.ClaimsProviderSetup not initialized, CP side decryption data missing");
			return Collections.emptyList();
		}
		List<ClaimsParty> claimsParties = relyingPartiesMapping.getClaimsProviderSetup().getClaimsParties();

		TreeSet<Credential> credentials = new TreeSet<>((Credential cred1, Credential cred2)
				-> getCredSubjectName(cred1).compareTo((getCredSubjectName(cred2))));

		for (var claimsParty : claimsParties) {
			var cred = claimsParty.getCpDecryptionCredentials();
			if (cred != null) {
				credentials.addAll(cred);
			}
		}
		return credentials.stream().toList();
	}

	public String getCredSubjectName(Credential credential){
		return ((X509Credential) credential).getEntityCertificate().getSubjectX500Principal().getName();
	}

	// SetupRP.ClientName is required to handle the %clientname% in assertion attributes (see replaceClientNameInUri)
	public String getRpClientName(RelyingParty relyingParty) {
		var clientName = relyingParty.getClientName();
		if (clientName == null) {
			log.debug("RP with id={} has no ClientName. Configure one even if not needed."
							+ " HINT: Check SetupRP.ClientName and Definition entries in SetupRP/ProfileRP containing "
							+ "%clientname%.", relyingParty.getId());
			clientName = "SetupRP.ClientName-Missing";
		}
		return clientName;
	}

	public String getRpClientExtId(RelyingParty relyingParty) {
		if (relyingParty.getClientExtId() != null) {
			return relyingParty.getClientExtId();
		}
		if (relyingParty.getIdmLookup() == null) {
			// AuthOnly case no IDM services involved
			log.debug("No IDMLookup for RP with ID={}", relyingParty.getId());
			return "";
		}
		Optional<String> clientExtId = getClientExtId(relyingParty.getIdmLookup());
		return clientExtId.orElse("");
	}

	public Optional<String> getClientExtId(IdmRequests idmRequests) {
		for (var idmService : idmQueryServices) {
			var result = idmService.getClientExtId(idmRequests);
			if (result.isPresent()) {
				return result;
			}
		}
		return Optional.empty();
	}

	public SsoGroup getSsoGroupConfig(String ssoGroupName) {
		return getSsoGroupConfig(ssoGroupName, false).orElse(null); // never null
	}

	public Optional<SsoGroup> getSsoGroupConfig(String ssoGroupName, boolean tryOnly) {
		// there are only a few SSO groups so linear search is no issue so far
		var ssoGroup = relyingPartiesMapping.getSsoGroupSetup().getSsoGroups().stream()
				.filter(group -> group.getName().equals(ssoGroupName)).findFirst();
		if (ssoGroup.isEmpty()) {
			if (tryOnly) {
				log.debug("Could not find ssoGroup={} (implicit group name built from the RP ID)", ssoGroupName);
			}
			else {
				throw new TechnicalException(String.format("Could not find ssoGroup=%s", ssoGroupName));
			}
		}
		return ssoGroup;
	}

	public long getTokenLifetime(RelyingParty relyingParty) {
		// Conditions and SubjectConfirmation timestamp per RP (cannot be set differently, WSTrust uses the global properties)
		var secPol = getSecurityPolicies(relyingParty);
		return PropertyUtil.evaluatePropery(
				secPol, SecurityPolicies::getNotOnOrAfterSeconds,
				() -> trustBrokerProperties.getSecurity().getTokenLifetimeSec() // not null
		).longValue();
	}

	public long getAudienceRestrictionLifetime(RelyingParty relyingParty) {
		// Conditions and SubjectConfirmation timestamp per RP (cannot be set differently, WSTrust uses the global properties)
		return PropertyUtil.evaluatePositiveNumberProperty(
				getSecurityPolicies(relyingParty), SecurityPolicies::getAudienceNotOnOrAfterSeconds,
				() -> getTokenLifetime(relyingParty) // not null
		).longValue(); // default is not null
	}

	public SecurityPolicies getPartySecurityPolicies(SAMLObject message) {
		if (message instanceof Response samlResponse && samlResponse.getIssuer() != null) {
			var claimsParty = getClaimsProviderSetupByIssuerId(samlResponse.getIssuer().getValue(), null, true);
			return getSecurityPolicies(claimsParty);
		}
		if (message instanceof RequestAbstractType samlRequest && samlRequest.getIssuer() != null) {
			var relyingParty = getRelyingPartyByIssuerIdOrReferrer(samlRequest.getIssuer().getValue(), null, true);
			return getSecurityPolicies(relyingParty);
		}
		if (message instanceof LogoutResponse logoutResponse && logoutResponse.getIssuer() != null) {
			var relyingParty = getRelyingPartyByIssuerIdOrReferrer(logoutResponse.getIssuer().getValue(), null, true);
			return getSecurityPolicies(relyingParty);
		}
		return null;
	}

	public ClaimsProvider getClaimsProviderById(RelyingParty relyingParty, String cpId) {
		ClaimsProviderMappings claimsProviderMappings = relyingParty.getClaimsProviderMappings();
		if (claimsProviderMappings == null || claimsProviderMappings.getClaimsProviderList() == null) {
			throw new TechnicalException(String.format(
					"Missing mapping in RelyingParty=%s for cpIssuer='%s'", relyingParty.getId(), cpId));
		}
		Optional<ClaimsProvider> claimsProvider =
				claimsProviderMappings.getClaimsProviderList().stream().filter(
						cp -> cp.getId().equalsIgnoreCase(cpId)).findFirst();
		if (claimsProvider.isEmpty()) {
			throw new TechnicalException(String.format(
					"Missing mapping RelyingParty=%s for cpIssuer='%s'", relyingParty.getId(), cpId));
		}
		return claimsProvider.get();
	}
}
