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

package swiss.trustbroker.config.dto;

import static org.springframework.security.saml2.core.Saml2X509Credential.Saml2X509CredentialType.VERIFICATION;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.opensaml.security.x509.X509Credential;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.AuthorizedApplication;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderDefinitions;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.FeatureEnum;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.federation.xmlconfig.SsoGroupSetup;
import swiss.trustbroker.util.HrdSupport;
import swiss.trustbroker.util.WebSupport;

/**
 * Relying party configuration - internal model.
 */
@Component
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class RelyingPartyDefinitions {

	private ClaimsProviderDefinitions claimsProviderDefinitions;

	private RelyingPartySetup relyingPartySetup;

	private ClaimsProviderSetup claimsProviderSetup;

	private SsoGroupSetup ssoGroupSetup;

	private Map<String, Pair<RelyingParty, OidcClient>> oidcConfigurations;

	private Map<String, Pair<RelyingParty, AuthorizedApplication>> accessRequestConfigurations;

	private OidcIdpCredential oidcIdpCredential;

	private static ClaimsProvider getSingleClaimsProvider(RelyingParty relyingParty) {
		return relyingParty.getClaimsProviderMappings() != null
				&& relyingParty.getClaimsProviderMappings().getClaimsProviderList() != null
				&& relyingParty.getClaimsProviderMappings().getClaimsProviderList().size() == 1 ?
				relyingParty.getClaimsProviderMappings().getClaimsProviderList().get(0)
				: null;
	}
	private static String getClientKey(String clientId, String cpId) {
		return cpId != null ? clientId + ">>" + cpId : clientId;
	}

	static void addOidcClient(Map<String, Pair<RelyingParty, OidcClient>> newConfigurations,
			OidcClient client, RelyingParty relyingParty) {
		if (client == null || client.getId() == null) {
			return;
		}

		// HRDs with only a single entry get an additional mapping
		var singleCp = getSingleClaimsProvider(relyingParty);
		if (singleCp != null) {
			// all values used for hrdHint matching must be registered
			addOidcClientForCp(newConfigurations, client, relyingParty, singleCp.getId(), "id");
			addOidcClientForCp(newConfigurations, client, relyingParty, singleCp.getName(), "name");
			addOidcClientForCp(newConfigurations, client, relyingParty, singleCp.getHrdHintAlias(), "hrdHintAlias");
		}

		// Last one of a SetupRP wins, and we only write an ERROR if a
		// HRD section differs (usually the reason why such RelyingParty setups have been coped).
		var oidcClientKey = client.getId();
		var replaced = newConfigurations.put(oidcClientKey, Pair.of(relyingParty, client));
		checkSetupRpDuplicate(relyingParty, client, replaced, singleCp != null ? singleCp.getId() : null);
	}

	private static void addOidcClientForCp(Map<String, Pair<RelyingParty, OidcClient>> newConfigurations, OidcClient client,
			RelyingParty relyingParty, String singleCpId, String singleCpIdType) {
		if (singleCpId == null) {
			return;
		}
		var oidcClientCpKey = getClientKey(client.getId(), singleCpId);
		var replaced = newConfigurations.put(oidcClientCpKey, Pair.of(relyingParty, client));
		log.debug("Added oidcClient={} to rpIssuer={} mapping for {}={}",
				client.getId(), relyingParty.getId(), singleCpIdType, singleCpId);
		checkSetupRpDuplicate(relyingParty, client, replaced, singleCpId);
	}

	// debugging copy & pasted SetupRP files containing the same Oidc Client entries
	private static void checkSetupRpDuplicate(
			RelyingParty relyingParty, OidcClient oidcClient,
			Pair<RelyingParty, OidcClient> replaced, String singleCpId) {
		if (replaced != null && !replaced.getKey().sameHrd(relyingParty)) {
			log.warn("Encountered oidcClient={} duplicate on rpIssuer={} for cpIssuer={} (or hrdHintAlias) lostRpIssuer={}."
							+ " NOTE: This can lead to arbitrary HRD CP selection."
							+ " HINT: It's recommended to 'optimize HRD' eliminating replication.",
					oidcClient.getId(), relyingParty.getId(), singleCpId, replaced.getKey().getId());
		}
	}

	public void loadOidcConfiguration(OidcProperties oidcProperties) {
		var relyingParties = this.relyingPartySetup.getRelyingParties();
		var newConfigurations = new HashMap<String, Pair<RelyingParty, OidcClient>>();
		for (RelyingParty relyingParty : relyingParties) {
			var oidcClients = relyingParty.getOidcClients();
			if (!oidcClients.isEmpty()) {
				oidcClients.forEach(client -> addOidcClient(newConfigurations, client, relyingParty));
				updateAcWhitelistFromOidcClients(relyingParty, oidcProperties);
			}
		}
		this.oidcConfigurations = newConfigurations;
		this.oidcIdpCredential = loadIdpCredentials(oidcProperties);
	}

	public void loadAccessRequestConfigurations() {
		var relyingParties = this.relyingPartySetup.getRelyingParties();
		var newConfigurations = new HashMap<String, Pair<RelyingParty, AuthorizedApplication>>();
		for (RelyingParty relyingParty : relyingParties) {
			var accessRequest = relyingParty.getAccessRequest();
			if (accessRequest != null && accessRequest.enabled() &&
					accessRequest.getAuthorizedApplications() != null &&
					accessRequest.getAuthorizedApplications().getAuthorizedApplicationList() != null) {

				accessRequest.getAuthorizedApplications().getAuthorizedApplicationList()
						.forEach(application -> addAuthorizedApplication(newConfigurations, application, relyingParty));
			}
		}
		this.accessRequestConfigurations = newConfigurations;
	}

	static void addAuthorizedApplication(Map<String, Pair<RelyingParty, AuthorizedApplication>> newConfigurations,
			AuthorizedApplication application, RelyingParty relyingParty) {
		if (application == null || application.getName() == null || relyingParty.getUnaliasedId() != null) {
			return;
		}
		var existing = newConfigurations.get(application.getName());
		if (existing != null) {
			var existingWithTrigger = Boolean.TRUE.equals(existing.getValue().getEnableTrigger());
			var currentWithTrigger = Boolean.TRUE.equals(application.getEnableTrigger());
			if (currentWithTrigger && existingWithTrigger) {
				log.error("Application={} already mapped to rpIssuerId={} with enableTrigger={} ignoring "
					+ "duplicateRpIssuerId={} with enableTrigger={} - fix config or the external trigger will not work!",
					application.getName(), existing.getKey().getId(), existingWithTrigger,
					relyingParty.getId(), currentWithTrigger);
				return;
			}
			else if (currentWithTrigger) {
				log.info("Application={} already mapped to rpIssuerId={} with enableTrigger={} overwriting with "
					+ "duplicateRpIssuerId={} with enableTrigger={}",
					application.getName(), existing.getKey().getId(), existingWithTrigger,
					relyingParty.getId(), currentWithTrigger);
			}
			else {
				log.info("Application={} already mapped to rpIssuerId={} with enableTrigger={} ignoring "
					+ "duplicateRpIssuerId={} with enableTrigger={}",
					application.getName(), existing.getKey().getId(), existingWithTrigger,
					relyingParty.getId(), currentWithTrigger);
				return;
			}
		}
		newConfigurations.put(application.getName(), Pair.of(relyingParty, application));
		log.debug("Application={} mapped to rpIssuerId={}", application.getName(), relyingParty.getId());
	}

	static void updateAcWhitelistFromOidcClients(RelyingParty relyingParty, OidcProperties oidcProperties) {
		var clients = relyingParty.getOidcClients();
		Set<String> calculatedAcsUrls = new HashSet<>();
		for (var client : clients) {
			calculateAclUrls(client, oidcProperties, calculatedAcsUrls);
		}
		if (!calculatedAcsUrls.isEmpty()) {
			if (relyingParty.getAcWhitelist() == null) {
				relyingParty.setAcWhitelist(new AcWhitelist());
			}
			if (relyingParty.getAcWhitelist().getAcUrls() != null) {
				calculatedAcsUrls.addAll(relyingParty.getAcWhitelist().getAcUrls());
			}
			relyingParty.getAcWhitelist().setAcUrls(List.copyOf(calculatedAcsUrls));
			log.debug("For rpId={} added calculated URLs to AcWhitelist: acWhitelistUrls={}",
					relyingParty.getId(), relyingParty.getAcWhitelist().getAcUrls());
		}
	}

	private static void calculateAclUrls(OidcClient client, OidcProperties oidcProperties, Set<String> calculatedAcsUrls) {
		var perimeterUrl = oidcProperties.getPerimeterUrl();
		if (!StringUtils.hasText(perimeterUrl)) {
			return;
		}
		try {
			// ensure there is at least one trailing slash (URI takes care of doubles)
			var uri = new URI(perimeterUrl + '/');
			calculatedAcsUrls.add(uri.resolve(client.getId()).toString());
		}
		catch (URISyntaxException ex) {
			throw new TechnicalException(String.format("Invalid oidc.perimeterUrls url=%s ex=%s",
					perimeterUrl, ex.getMessage()), ex);
		}
	}

	private static OidcIdpCredential loadIdpCredentials(OidcProperties oidcProperties) {
		var signer = oidcProperties.getIdentityProvider().getSigner();
		var credential = CredentialReader.createCredential(signer);
		var certificate = ((X509Credential)credential).getEntityCertificate();
		var verificationCertificate = new Saml2X509Credential(certificate, VERIFICATION);
		var signing = Saml2X509Credential.signing(credential.getPrivateKey(), certificate);

		OidcIdpCredential idpCredential = new OidcIdpCredential();
		idpCredential.setSigner(signing);
		idpCredential.setTrust(verificationCertificate);
		return idpCredential;
	}

	// We need this special lookup to deal with Oidc.Client setups attached to multiple SetupRP (legacy copy&paste).
	// On startup this ambiguity is actually reported as an ERROR but old habits die hard.
	// Picking the right config is best-effort and if they copied configs are aligned it even works as expected.
	private Pair<RelyingParty, OidcClient> getRelyingPartyOidcPair(String clientId, TrustBrokerProperties properties) {
		Pair<RelyingParty, OidcClient> ret = null;
		if (oidcConfigurations != null) {
			// CP selection applied
			var cpHint = HrdSupport.getClaimsProviderHint(properties);
			ret = oidcConfigurations.get(getClientKey(clientId, cpHint));
			log.debug("Getting oidcClient={} with cpHint={} resulted in relyingParty={} with federationId={}",
					clientId, cpHint, ret != null ? ret.getLeft().getId() : null,
					ret != null ? ret.getValue().getFederationId() : null);
			if (ret != null) {
				return ret;
			}
			// only client_id applied
			ret = oidcConfigurations.get(clientId);
		}
		log.debug("Getting oidcClient={} with cpHint=null resulted in relyingParty={} with federationId={}",
				clientId, ret != null ? ret.getKey().getId() : null,
				ret != null ? ret.getValue().getFederationId() : null);
		return ret;
	}

	public Optional<OidcClient> getOidcClientConfigById(String clientId, TrustBrokerProperties properties) {
		var entry = getRelyingPartyOidcPair(clientId, properties);
		return entry != null ? Optional.of(entry.getValue()) : Optional.empty();
	}

	private Optional<RelyingParty> getRelyingPartyByClientId(String clientId, TrustBrokerProperties properties) {
		var entry = getRelyingPartyOidcPair(clientId, properties);
		return entry != null ? Optional.of(entry.getKey()) : Optional.empty();
	}

	// pre-condition check on accessing the OIDC part of our service
	public RelyingParty getRelyingPartyByOidcClientId(String clientId, String realmName,
			TrustBrokerProperties properties, boolean tryOnly) {
		var relyingParty = getRelyingPartyByClientId(clientId, properties);
		if (relyingParty.isEmpty()) {
			missingOidcClient(clientId, realmName, tryOnly);
		}
		return relyingParty.orElse(null);
	}

	public Pair<RelyingParty, OidcClient> getRelyingPartyOidcClientByOidcClientId(String clientId, String realmName,
			TrustBrokerProperties properties, boolean tryOnly) {
		var entry = getRelyingPartyOidcPair(clientId, properties);
		if (entry == null) {
			missingOidcClient(clientId, realmName, tryOnly);
		}
		return entry;
	}

	private static void missingOidcClient(String clientId, String realmName, boolean tryOnly) {
		var msg = String.format(
				"OIDC client mapping failed with clientId=%s on realmName=%s (no relying party found). " +
				"HINT: Check service startup for 'Invalid configFile' messages and fix rejected setups.",
				clientId, realmName);
		if (!tryOnly) {
			throw new RequestDeniedException(msg);
		}
		log.error(msg);
	}

	public Optional<Pair<RelyingParty, AuthorizedApplication>> getRelyingPartyByAuthorizedApplication(String application) {
		return Optional.ofNullable(accessRequestConfigurations.get(application));
	}

	// WARNING: Use just for decisions, do not use for SAML dispatching as HRD hinting is not supported
	public Optional<OidcClient> getOidcClientByPredicate(Predicate<OidcClient> predicate) {
		var clients = getOidcClientsByPredicate(predicate);
		if (clients.isEmpty()) {
			return Optional.empty();
		}
		return Optional.of(clients.get(0));
	}

	public List<OidcClient> getOidcClientsByPredicate(Predicate<OidcClient> predicate) {
		if (oidcConfigurations == null) {
			return Collections.emptyList();
		}
		return oidcConfigurations.values().stream()
				.map(Pair::getValue)
				.filter(predicate)
				.distinct()
				.toList();
	}

	public boolean isRpDisabled(RelyingParty relyingParty, HttpServletRequest httpRequest,
			NetworkConfig networkConfig) {
		return relyingParty != null && FeatureEnum.FALSE.equals(relyingParty.getEnabled())
				&& !WebSupport.canaryModeEnabled(httpRequest, networkConfig);
	}
}
