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

package swiss.trustbroker.oidc.cache.service;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import io.micrometer.core.annotation.Timed;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.tracing.Traced;
import swiss.trustbroker.common.util.HttpUtil;
import swiss.trustbroker.common.util.JsonUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethod;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethods;
import swiss.trustbroker.federation.xmlconfig.CounterParty;
import swiss.trustbroker.federation.xmlconfig.OidcClaimsSource;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.OidcHttpClientProvider;
import swiss.trustbroker.oidc.client.dto.OpenIdProviderConfiguration;

/**
 * Service for OIDC metadata configuration fetching.
 *
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OIDC Metadata</a>
 */
@Service
@AllArgsConstructor
@Slf4j
public class OidcMetadataCacheService {

	@Data
	private static class CacheEntry {

		private final long createTimeMillis;

		private final OpenIdProviderConfiguration config;

		private CacheEntry(OpenIdProviderConfiguration config) {
			this.config = config;
			this.createTimeMillis = System.currentTimeMillis();
		}

		private boolean keep(long minimumCacheTimeSecs) {
			return (System.currentTimeMillis() - createTimeMillis) < (minimumCacheTimeSecs * 1000L);
		}

	}

	// fields in metadata

	private static final String METADATA_ISSUER = "issuer";

	private static final String METADATA_AUTHORIZATION_ENDPOINT = "authorization_endpoint";

	private static final String METADATA_JWKS_URI = "jwks_uri";

	private static final String METADATA_TOKEN_ENDPOINT = "token_endpoint";

	private static final String METADATA_TOKEN_AUTH_METHODS = "token_endpoint_auth_methods_supported";

	private static final String METADATA_USERINFO_ENDPOINT = "userinfo_endpoint";

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final GlobalExceptionHandler globalExceptionHandler;

	private final OidcHttpClientProvider httpClientProvider;

	private final OidcClientSecretResolver clientSecretProvider;

	private final TrustBrokerProperties trustBrokerProperties;

	private final ExecutorService executorService;

	private final Map<String, CacheEntry> oidcConfigurations = new ConcurrentHashMap<>();

	/**
	 * Provide key by token key ID.
	 * <br/>
	 * Fetches OIDC metadata again if the key is not present.
	 */
	public Optional<JWK> getKey(ClaimsParty claimsParty, String expectedKid) {
		if (expectedKid == null) {
			return Optional.empty();
		}
		var oidcClient = claimsParty.getSingleOidcClient();
		var cacheEntry = getCachedConfig(claimsParty, oidcClient);
		var key = cacheEntry.getConfig().getJwkSet().getKeyByKeyId(expectedKid);
		if (key == null) {
			var cacheEntryOpt = refreshCachedConfig(claimsParty, oidcClient);
			if (cacheEntryOpt.isPresent()) {
				// single retry to check if we missed a key rotation
				log.info("Unknown kid={} from cpIssuer={}, try retrieving JWKs once", expectedKid, claimsParty.getId());
				key = cacheEntryOpt.get().getConfig().getJwkSet().getKeyByKeyId(expectedKid);
			}
		}
		return Optional.ofNullable(key);
	}

	public OpenIdProviderConfiguration getOidcConfiguration(ClaimsParty claimsParty) {
		var oidcClient = claimsParty.getSingleOidcClient();
		return getCachedConfig(claimsParty, oidcClient).getConfig();
	}

	public OpenIdProviderConfiguration getOidcConfiguration(CounterParty counterParty, OidcClient oidcClient) {
		return getCachedConfig(counterParty, oidcClient).getConfig();
	}

	private CacheEntry getCachedConfig(CounterParty claimsParty, OidcClient oidcClient) {
		return oidcConfigurations.computeIfAbsent(oidcClient.getId(),
				clientId -> new CacheEntry(fetchProviderMetadata(oidcClient, claimsParty.getCertificates())));
	}

	private Optional<CacheEntry> refreshCachedConfig(CounterParty claimsParty, OidcClient oidcClient) {
		var cacheEntry = oidcConfigurations.get(oidcClient.getId());
		if (cacheEntry != null) {
			long minimumCacheTimeSecs = trustBrokerProperties.getOidc().getMinimumMetadataCacheTimeSecs();
			if (cacheEntry.keep(minimumCacheTimeSecs)) {
				log.info("Skipped reload of OIDC metadata for clientId={} loaded less than minimumCacheTimeSecs={} ago",
						oidcClient.getId(), minimumCacheTimeSecs);
				return Optional.empty();
			}
		}
		cacheEntry = new CacheEntry(fetchProviderMetadata(oidcClient, claimsParty.getCertificates()));
		oidcConfigurations.put(oidcClient.getId(), cacheEntry);
		return Optional.of(cacheEntry);
	}

	// asynchronous execution
	public void triggerRefreshConfigurations() {
		executorService.submit(this::refreshConfigurations);
	}

	@Scheduled(cron = "${trustbroker.config.oidc.syncSchedule}")
	@Traced
	@Timed("oidc_metadata_fetch")
	public void refreshConfigurations() {
		var loadCount = 0;
		var start = System.currentTimeMillis();

		Map<OidcClient, CounterParty> clientCertMap = new HashMap<>();
		for (var rp : relyingPartyDefinitions.getClaimsProviderSetup().getClaimsParties()) {
			getCounterPartyMap(rp, clientCertMap, true);
		}
		for (var rp : relyingPartyDefinitions.getRelyingPartySetup().getRelyingParties()) {
			getCounterPartyMap(rp, clientCertMap, false);
		}

		loadCount = loadConfigForCounterParty(clientCertMap, loadCount);

		var dTms = System.currentTimeMillis() - start;
		var failCount = clientCertMap.size() - loadCount;
		log.info("OIDC client configuration update done for claimsPartyCount={} in dtMs={} with failCount={}",
				clientCertMap.size(), dTms, failCount);
	}

	void getCounterPartyMap(CounterParty counterParty, Map<OidcClient, CounterParty> clientCertMap, boolean requiresEndpoint) {
		if (counterParty.useOidc() && !counterParty.getOidcClients().isEmpty()) {
			for (var client : counterParty.getOidcClients()) {
				if (client.getProtocolEndpoints() != null) {
					clientCertMap.put(client, counterParty);
				} else if (requiresEndpoint) {
					log.error("OIDC client={} ProtocolEndpoint is missing", client.getId());
				}
			}
		}
	}

	private int loadConfigForCounterParty(Map<OidcClient, CounterParty> counterParties, int loadCount) {
		log.info("OIDC client configuration update for counterPartyCount={}", counterParties.size());
		for (var entry : counterParties.entrySet()) {
			var counterParty = entry.getValue();
			try {
				var oidcClient = entry.getKey();
				if (oidcClient.getProtocolEndpoints() == null) {
					log.debug("OIDC client={} protocol endpoint is null", oidcClient.getId());
					continue;
				}
				var cacheEntry = refreshCachedConfig(counterParty, oidcClient);
				if (cacheEntry.isPresent()) {
					++loadCount;
				}
				// else: entry too new for refresh
			}
			catch (RuntimeException ex) {
				// publish issues in status API:
				counterParty.initializedValidationStatus().addException(ex);
				globalExceptionHandler.logException(ex);
			}
		}
		return loadCount;
	}

	// cache miss or missing JWK, trigger a refresh
	public OpenIdProviderConfiguration fetchProviderMetadata(OidcClient client, Certificates certificates) {
		var configurationUrl = getConfigurationUrl(client);
		try {
			var metadataUri = WebUtil.getValidatedUri(configurationUrl);
			if (metadataUri == null) {
				throw new TechnicalException(String.format("oidcClientId=%s has missing or invalid configurationUrl=%s",
						client.getId(), configurationUrl));
			}
			var httpClient = httpClientProvider.createHttpClient(client, certificates, metadataUri);

			// fetch metadata
			var start = System.currentTimeMillis();
			var metadataResponse = HttpUtil.getHttpResponseString(httpClient, metadataUri);
			if (metadataResponse.isEmpty()) {
				throw new TechnicalException(String.format("oidcClientId=%s failed to fetch configurationUrl=%s",
						client.getId(), configurationUrl));
			}
			var result = parseOidcMetadata(metadataResponse.get(), client);
			log.debug("oidcClient={} configurationUrl={} returned result={}", client.getId(), configurationUrl, result);
			if (client.getIssuerId() != null && !client.getIssuerId().equals(result.getIssuerId())) {
				log.info("oidcClient={} has issuerId={} but configurationUrl={} returned issuerId={}",
						client.getId(), client.getIssuerId(), configurationUrl, result.getIssuerId());
			}
			var jwksResponse = HttpUtil.getHttpResponseStream(httpClient, result.getJwkEndpoint());
			if (jwksResponse.isEmpty()) {
				throw new TechnicalException(String.format("oidcClientId=%s failed to fetch configurationUrl=%s",
						client.getId(), configurationUrl));
			}
			var jwkSet = JWKSet.load(jwksResponse.get());
			result.setJwkSet(jwkSet);

			var clientSecret = clientSecretProvider.resolveClientSecret(client);
			result.setClientSecret(clientSecret);

			// done
			var dTms = System.currentTimeMillis() - start;
			log.info("Loaded oidcClientId={} from configurationUrl={} in dTms={} : result={}",
					client.getId(), configurationUrl, dTms, result);
			validateMetadata(client, result);
			return result;
		}
		catch (IOException | ParseException ex) {
			throw new TechnicalException(String.format("oidcClientId=%s failed to fetch configurationUrl=%s message=%s",
					client.getId(), configurationUrl, ex.getMessage()), ex);
		}
	}

	private static OpenIdProviderConfiguration parseOidcMetadata(String jsonString, OidcClient oidcClient) {
		var metadataMap = JsonUtil.parseJsonObject(jsonString, false);
		var issuerId = JsonUtil.getField(metadataMap, METADATA_ISSUER, String.class);
		var authorizationEndpoint = getUri(metadataMap, METADATA_AUTHORIZATION_ENDPOINT, oidcClient);
		var jwkEndpoint = getUri(metadataMap, METADATA_JWKS_URI, oidcClient);
		var tokenEndpoint = getUri(metadataMap, METADATA_TOKEN_ENDPOINT, oidcClient);
		var tokenAuthMethods = JsonUtil.getField(metadataMap, METADATA_TOKEN_AUTH_METHODS, List.class);
		var authenticationMethods = getClientAuthenticationMethods(tokenAuthMethods);
		var userinfoEndpoint = getUri(metadataMap, METADATA_USERINFO_ENDPOINT, oidcClient);
		return OpenIdProviderConfiguration.builder()
										  .issuerId(issuerId)
										  .authorizationEndpoint(authorizationEndpoint)
										  .jwkEndpoint(jwkEndpoint)
										  .tokenEndpoint(tokenEndpoint)
										  .userinfoEndpoint(userinfoEndpoint)
										  .authenticationMethods(authenticationMethods)
										  .build();
	}

	private static ClientAuthenticationMethods getClientAuthenticationMethods(List<?> tokenAuthMethods) {
		if (tokenAuthMethods == null) {
			return new ClientAuthenticationMethods(Collections.emptyList());
		}
		var methodList = tokenAuthMethods.stream().map(ClientAuthenticationMethod::valueOfIgnoreCase).toList();
		return new ClientAuthenticationMethods(methodList);
	}

	static void validateMetadata(OidcClient client, OpenIdProviderConfiguration metadata) {
		if (metadata.getIssuerId() == null) {
			if (client.getIssuerId() == null) {
				throw new TechnicalException(String.format("OIDC client=%s metadata did not return an %s",
						client.getId(), METADATA_ISSUER));
			}
			else {
				log.info("OIDC client={} metadata did not return an issuer - using issuer={} from config",
						client.getId(), client.getIssuerId());
			}
		}
		if (metadata.getAuthorizationEndpoint() == null) {
			throw new TechnicalException(String.format("OIDC client=%s metadata did not return an %s",
					client.getId(), METADATA_AUTHORIZATION_ENDPOINT));
		}
		if (metadata.getTokenEndpoint() == null) {
			throw new TechnicalException(String.format("OIDC client=%s metadata did not return a %s",
					client.getId(), METADATA_TOKEN_ENDPOINT));
		}
		if (metadata.getUserinfoEndpoint() == null && client.useClaimsFromSource(OidcClaimsSource.USERINFO)) {
			throw new TechnicalException(String.format("OIDC client=%s metadata did not return a %s for claimsFromUserinfo=true",
					client.getId(), METADATA_USERINFO_ENDPOINT));
		}
		if (metadata.getJwkEndpoint() == null) {
			throw new TechnicalException(String.format("OIDC client=%s metadata did not return a %s",
					client.getId(), METADATA_JWKS_URI));
		}
		var authenticationMethods = metadata.getAuthenticationMethods() != null ?
				metadata.getAuthenticationMethods().getMethods() : null;
		if (CollectionUtils.isEmpty(authenticationMethods) ||
				(!authenticationMethods.contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) &&
						!authenticationMethods.contains(ClientAuthenticationMethod.CLIENT_SECRET_POST))) {
			// default CLIENT_SECRET_BASIC used
			log.warn("OIDC client={} metadata did not return any supported {}={}",
					client.getId(), METADATA_TOKEN_AUTH_METHODS, authenticationMethods);
		}
		log.debug("OIDC metadata from client={} is valid", client.getId());
	}

	private static URI getUri(Map<String, Object> metadataMap, String key, OidcClient client) {
		var value = JsonUtil.getField(metadataMap, key, String.class);
		var uri = WebUtil.getValidatedUri(value);
		if (uri == null) {
			var configurationUrl = getConfigurationUrl(client);
			throw new TechnicalException(String.format(
					"oidcClientId=%s configurationUrl=%s has missing or invalid %s=%s",
					client.getId(), configurationUrl, key, value));
		}
		return uri;
	}

	private static String getConfigurationUrl(OidcClient client) {
		if (client.getProtocolEndpoints() == null) {
			return null;
		}
		return client.getProtocolEndpoints().getMetadataUrl();
	}

	// For tests.
	// Not called after config refresh. Some no longer referenced entries could thus remain in the cache,
	// but entries consume only little memory.
	void flushCache() {
		oidcConfigurations.clear();
		log.info("Flushed cache");
	}
}
