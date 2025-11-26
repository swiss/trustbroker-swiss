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

package swiss.trustbroker.oidc;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.google.common.base.Functions;
import com.google.common.collect.Lists;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.AttributeRegistry;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.UrlAcceptor;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.AuthorizationGrantType;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethod;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Multivalued;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.OidcSecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Scope;
import swiss.trustbroker.mapping.service.ClaimsMapperService;
import swiss.trustbroker.oidc.session.OidcSessionSupport;

@Slf4j
public class OidcConfigurationUtil {

	private OidcConfigurationUtil() {
	}

	// Method not synchronized because we do RegisterClient caching on startup and refresh only
	// Per default we set up a mixed FE/BE case.
	static RegisteredClient createRegisteredClient(OidcClient client, long defaultTokenTimeSec, long defaultCodeTimeSec) {
		// NOTE: Compiled in defaults, use templating instead by putting this into ProfileRP >> RelyingParty >> Oidc >> Client
		var polices = client.getOidcSecurityPolicies() != null
				? client.getOidcSecurityPolicies()
				: defaultSecurityPolicies(defaultTokenTimeSec); // align on SAML assertion config
		var clientAuthenticationMethods =
				client.getClientAuthenticationMethods() != null
						? client.getClientAuthenticationMethods().getMethods()
						: ClientAuthenticationMethod.defaultValues();
		var authorizationGrantTypes =
				client.getAuthorizationGrantTypes() != null
						? client.getAuthorizationGrantTypes().getGrantTypes()
						: AuthorizationGrantType.defaultValues();
		var configuredScopes =
				client.getScopes() != null
						? client.getScopes().getScopeList()
						: Scope.defaultNames();
		var clientId = client.getId();
		log.debug("Using Oidc Client with clientId={} authenticationMethods='{}', authorizationGrantTypes='{}' scopes='{}'",
				clientId, clientAuthenticationMethods, authorizationGrantTypes, configuredScopes);

		// spring security OIDC registry entry
		var clientSettings = getClientSettings(polices);
		var tokenSettings = getTokenSettings(polices, defaultTokenTimeSec, defaultCodeTimeSec);

		// construct it
		var registeredClient = RegisteredClient.withId(clientId)
				.clientId(clientId)
				// Must be unique/client
				.clientSecret(completeSecret(client.getClientSecret()))
				.clientSettings(clientSettings)
				.clientAuthenticationMethods(authenticationMethods ->
						clientAuthenticationMethods.forEach(authenticationMethod ->
								authenticationMethods.add(authenticationMethod.getMethod())))
				.authorizationGrantTypes(grantTypes ->
						authorizationGrantTypes.forEach(
								grantType -> grantTypes.add(grantType.getType())))
				.scopes(scopes -> scopes.addAll(configuredScopes))
				// RedirectUris is a mandatory field for a Registered client (we don't distinguish between login and logout URIs)
				// postLogoutRedirectUris is not set, required for Spring's OidcLogoutAuthenticationValidator,
				// but not without CustomEndpointInterceptor
				.redirectUris(uris -> uris.addAll(client.getRedirectUris().getRedirectUrls()))
				.tokenSettings(tokenSettings)
				.build();

		// validation and init/refresh logging
		var clientAuth = registeredClient.getClientAuthenticationMethods();
		var frontendClient = clientAuth.contains(ClientAuthenticationMethod.NONE.getMethod());
		var backendClient = (clientAuth.size() > 1 || !frontendClient) && registeredClient.getClientSecret() != null;
		var broken = !(frontendClient || backendClient);
		var fixHint1 = "HINT (FE): requireProofKey=true,ClientAuthenticationMethod=none";
		var fixHint2 = "HINT (BE): requireProofKey=false,ClientSecret=***,ClientAuthenticationMethod=client_secret_basic";
		var fixHint3 = "HINT (FE+BE): requireProofKey=false,ClientSecret=***,ClientAuthenticationMethod=none,client_secret_basic";
		log.info("OIDC registry cached clientId={} clientFlows='{}{}{}' tokenTimeToLiveMin={} refreshSupport={}",
				registeredClient.getClientId(),
				frontendClient ? "frontend/PKCE" : "",
				broken ? "N/A" : "",
				backendClient ? "backend/secret" : "",
				polices.getTokenTimeToLiveMin(),
				backendClient);
		client.setRegisteredClient(registeredClient);
		if (broken) {
			log.warn("Check OIDC clientId={} configuration ({}. {}. {}.)", clientId, fixHint1, fixHint2, fixHint3);
		}

		return registeredClient;
	}

	static Map<String, List<Object>> extractSamlAttributesFromContext(JwtEncodingContext context) {
		Map<String, List<Object>> attributes = new HashMap<>();
		var samlAuthPrincipal = OidcSessionSupport.getSamlPrincipalFromAuthentication(context.getPrincipal(), null);
		if (samlAuthPrincipal != null) {
			attributes = samlAuthPrincipal.getAttributes();
			// check on OriginalIssuer §duplicates and throw out same values
			deduplicateOriginalIssuerDuplicates(attributes);
			// populate nameidentifier as well, so we can address the subject NameID sow OIDC mapping can consume it as well
			if (attributes != null && attributes.get(CoreAttributeName.NAME_ID.getNamespaceUri()) == null) {
				var principalName = context.getPrincipal().getName();
				log.debug("Populating nameIDAttr={} with principal={} from SAML subject",
						CoreAttributeName.NAME_ID.getNamespaceUri(), principalName);
				var nameId = new ArrayList<>();
				nameId.add(principalName);
				attributes.put(CoreAttributeName.NAME_ID.getNamespaceUri(), nameId);
			}
		}
		return attributes;
	}

	static void deduplicateOriginalIssuerDuplicates(Map<String, List<Object>> attributes) {
		if (attributes != null) {
			attributes.forEach((k, v) -> {
				if (v != null && v.size() > 1) {
					// List must be mutable otherwise Jackson ObjectMapper can not deserialize
					@SuppressWarnings("java:S6204")
					var setList = v.stream().distinct().collect(Collectors.toList());
					if (setList.size() < v.size()) {
						attributes.put(k, setList);
					}
				}
			});
		}
	}

	static ClientSettings getClientSettings(OidcSecurityPolicies oidcSecurityPolicies) {
		var builder = ClientSettings.builder();
		if (Boolean.TRUE.equals(oidcSecurityPolicies.getRequireProofKey())) {
			builder.requireProofKey(true);
		}
		// unused
		if (Boolean.TRUE.equals(oidcSecurityPolicies.getRequireAuthorizationConsent())) {
			builder.requireAuthorizationConsent(true);
		}
		return builder.build();
	}

	static TokenSettings getTokenSettings(OidcSecurityPolicies oidcSecurityPolicies,
			long defaultTokenTimeSecs, long defaultCodeTimeSecs) {
		var builder = TokenSettings.builder();
		var tokenTtlSecs = defaultTokenTimeSecs;
		var refreshTokenTtlSecs = tokenTtlSecs;
		var codeTtlSecs = defaultCodeTimeSecs;
		var reuseRefreshToken = true; // resilience over security?
		var idTokenSignature = SignatureAlgorithm.RS256;
		var requireOpaqueAccessToken = false;
		if (oidcSecurityPolicies != null) {
			if (oidcSecurityPolicies.getAccessTokenTimeToLiveMin() != null) {
				tokenTtlSecs = oidcSecurityPolicies.getAccessTokenTimeToLiveMin() * 60L;
			}
			if (oidcSecurityPolicies.getRefreshTokenTimeToLiveMin() != null) {
				refreshTokenTtlSecs = oidcSecurityPolicies.getRefreshTokenTimeToLiveMin() * 60L;
			}
			if (oidcSecurityPolicies.getReuseRefreshTokens() != null) {
				reuseRefreshToken = oidcSecurityPolicies.getReuseRefreshTokens();
			}
			if (oidcSecurityPolicies.getAuthorizationCodeTimeToLiveMin() != null) {
				codeTtlSecs = oidcSecurityPolicies.getAuthorizationCodeTimeToLiveMin() * 60L;
			}
			if (oidcSecurityPolicies.getIdTokenSignature() != null) {
				idTokenSignature = SignatureAlgorithm.from(oidcSecurityPolicies.getIdTokenSignature());
			}
			requireOpaqueAccessToken = Boolean.TRUE.equals(oidcSecurityPolicies.getRequireOpaqueAccessToken());
		}

		// code
		builder.authorizationCodeTimeToLive(Duration.ofSeconds(codeTtlSecs));

		// token/access_token (JWT token, with OPAQUE tokens we could prevent OIDC miss-use forcing applications to use id_token)
		builder.accessTokenTimeToLive(Duration.ofSeconds(tokenTtlSecs));
		builder.accessTokenFormat(requireOpaqueAccessToken ? OAuth2TokenFormat.REFERENCE : OAuth2TokenFormat.SELF_CONTAINED);

		// id_token (lifecycle and content aligned with access_token)
		builder.idTokenSignatureAlgorithm(idTokenSignature); // many adapters only support RS256

		// refresh_token
		builder.refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenTtlSecs));
		builder.reuseRefreshTokens(reuseRefreshToken);

		return builder.build();
	}

	static OidcSecurityPolicies defaultSecurityPolicies(long defaultTokenTimeSec) {
		var defaultTokenTimeMin = (int) TimeUnit.SECONDS.toMinutes(defaultTokenTimeSec);
		return OidcSecurityPolicies.builder()
				.requireProofKey(true)
				.requireAuthorizationConsent(false)
				.tokenTimeToLiveMin(defaultTokenTimeMin)
				.accessTokenTimeToLiveMin(defaultTokenTimeMin) // no id_token TTL in spring so also applies to id_token?
				.refreshTokenTimeToLiveMin(defaultTokenTimeMin) // refresh aligned with 60min TTL
				.build();
	}

	static String getClientIdFromRequestUri(HttpServletRequest httpServletRequest) {
		String[] uriElements = httpServletRequest.getRequestURI().split("/");
		int length = uriElements.length;
		return uriElements[length - 1];
	}

	static String getClientIdFromRequest(HttpServletRequest httpServletRequest) {
		var clientId = httpServletRequest.getParameter(OidcUtil.OIDC_CLIENT_ID);
		if (clientId == null) {
			clientId = getClientIdFromRequestUri(httpServletRequest);
		}
		return clientId;
	}

	static Map<Definition, List<String>> mapSamlNamesToDefs(Map<String, List<Object>> samlAttributes) {
		var ret = new HashMap<Definition, List<String>>();
		samlAttributes.forEach((k, v) -> {
			var attr = AttributeRegistry.forName(k); // registered attribute with pre-defined names?
			var shortName = attr != null ? attr.getName() : k;
			var newKey = Definition.builder() // no details from attribute repository, use FQ name for mapping
					.name(shortName)
					.namespaceUri(k)
					.build();
			var sv = Lists.transform(v, Functions.toStringFunction()); // strings only in SAMl world
			ret.put(newKey, sv);
		});
		return ret;
	}

	public static List<Definition> getAllOidcDefinitions(
			RelyingParty relyingParty, OidcClient oidcClient, Set<String> authorizedScopes) {
		var definitions = new ArrayList<Definition>();
		if (relyingParty == null) {
			log.info("OIDC claims are empty for oidcClient='{}' not having RP definitions", oidcClient);
			return definitions; // no RP? filter removes everything
		}

		// RP definitions
		var rpSelection = relyingParty.getAllDefinitions();
		filterDefinitions(rpSelection, definitions, authorizedScopes, relyingParty.getId());

		// OIDC client definitions
		if (oidcClient != null && oidcClient.getClaimsSelection() != null) {
			var oidcSelection = oidcClient.getClaimsSelection().getDefinitions();
			filterDefinitions(oidcSelection, definitions, authorizedScopes, oidcClient.getId());
		}
		return definitions;
	}

	private static void filterDefinitions(List<Definition> selection, List<Definition> definitions,
			Set<String> authorizedScopes, String relyingPartyId) {
		if (selection != null && authorizedScopes != null) {
			filterDefinitionList(selection, definitions, authorizedScopes, relyingPartyId);
		}
		if (authorizedScopes == null) {
			log.warn("Missing Scope from request. Tokens will have no claims");
		}
	}

	private static void filterDefinitionList(List<Definition> selection, List<Definition> definitions,
			Set<String> authorizedScopes, String relyingPartyId) {
		selection.stream()
				.filter(definition -> {
					var scope = definition.getScope();
					if (definition.getOidcNames() != null && scope == null) {
						scope = OidcUtil.DEFAULT_SCOPE;
						log.debug("No scope for definition={} for rp={} => using compatibility openid semantics with scope={}",
								definition.getName(), relyingPartyId, scope);
					}
					// scope is single valued, if we support 'scopes' in config, use intersection match here
					return definition.getOidcNames() != null && authorizedScopes.contains(scope);
				})
				.forEachOrdered(definitions::add);
	}

	public static Map<String, Object> computeOidcClaims(
			Map<String, List<Object>> attributesFromContext,
			List<Definition> definitions,
			ClaimsMapperService claimsMapperService,
			boolean addStandardClaims,
			OidcClient oidcClient) {
		// we allow this one to be manipulated in CpResponse.claims based on CpResponse.attributes
		var map = new HashMap<String, Object>();
		if (definitions.isEmpty()) {
			return map;
		}

		// Map definitions to key/values map supporting String or List<String> etc.
		// We support Definition with a value as ConstAttr without an incoming SAML attribute.
		for (Definition definition : definitions) {
			var values = getOidcMappableValues(attributesFromContext, definition);
			if (values == null) {
				continue;
			}
			// apply mappers on all OIDC marked values including constants
			if (claimsMapperService != null) { // null mainly for tests
				values = claimsMapperService.applyMappers(definition, values, "OIDC claims");
			}
			var clientId = oidcClient != null ? oidcClient.getId() : "NONE";
			addClaimsToMap(map, definition, values, clientId, false);
			// NOTE: The addStandardClaims flag is disabled per default to not have any implicit behavior
			if (addStandardClaims) {
				addStandardClaims(map, definition, values, clientId);
			}
		}
		return map;
	}

	private static List<Object> getOidcMappableValues(Map<String, List<Object>> attributes, Definition definition) {
		List<Object> ret = null;
		if (definition.getOidcNames() != null) {
			// SAML attribute input
			var namespaceUri = definition.getNamespaceUri();
			if (namespaceUri != null) {
				ret = attributes.get(namespaceUri);
			}
			// ConstAttr value(s)
			if (ret == null && !definition.getMultiValues().isEmpty()) {
				ret = new ArrayList<>(definition.getMultiValues());
			}
		}
		return ret;
	}

	private static void addStandardClaims(Map<String, Object> attributes, Definition definition, List<Object> values,
			String clientId) {
		// standard claim with OIDC mappings when no oidcNames is defined
		var standardClaim = getOidcStandardClaimName(definition);
		if (standardClaim != null && definition.getOidcNames() == null) {
			for (var oidcName : standardClaim.getOidcNameList()) {
				addClaimsToMap(attributes, new Definition(oidcName), values, clientId, true);
			}
		}
	}

	static void addClaimsToMap(Map<String, Object> claimMap, Definition definition, List<Object> values,
			String oidcClientId, boolean isStandard) {
		var allValues = values;
		var oidcNames = definition.getOidcNameList();
		var multiValued = definition.getMultiValued();
		for (String oidcName : oidcNames) {
			if (claimMap.containsKey(oidcName)) {
				allValues = getOidcAttributeValues(claimMap, oidcName, values);
				log.debug("Aggregating oidcName={} adding newValues={}", oidcName, values);
			}
			else {
				log.debug("Adding oidcName={} values={}", oidcName, values);
			}

			if (isStandard) {
				multiValued = Multivalued.ORIGINAL;
			}

			// Single value: We discard the array and make it a value directly (OIDC supports that)
			switch (multiValued) {
				case ORIGINAL:
					claimMap.put(oidcName, allValues.size() != 1 ? allValues : allValues.get(0));
					break;
				case LIST:
					claimMap.put(oidcName, allValues);
					break;
				case STRING:
					claimMap.put(oidcName, getStringValueOfOidcClaim(allValues));
					break;
				case ERROR:
					if (allValues.size() > 1) {
						throw new TechnicalException(String.format(
								"Invalid claim=%s in client config=%s Expected String but received List", oidcName,
								oidcClientId));
					}
					claimMap.put(oidcName, getStringValueOfOidcClaim(allValues));
					break;
				default:
					throw new TechnicalException(String.format(
							"Invalid multiValuedConfig=%s for clientId=%s", multiValued, oidcClientId));
			}
		}
	}

	static Object getStringValueOfOidcClaim(List<Object> allValues) {
		if (allValues.size() == 1) {
			return allValues.get(0);
		}
		if (allValues.size() > 1) {
			return StringUtils.join(allValues, " ");
		}
		return null;
	}

	static List<Object> getOidcAttributeValues(
			Map<String, Object> attributes, String oidcName, List<Object> newValues) {
		// new claim, use passed values as is, no copy, no aggregation, no de-deduplication
		var claimValue = attributes.get(oidcName);
		if (claimValue == null) {
			return newValues;
		}
		// aggregate, de-duplicate
		var allValues = new ArrayList<>();
		if (claimValue instanceof List<?> oldValues) {
			allValues.addAll(oldValues);
		}
		else {
			allValues.add(claimValue);
		}
		for (var newValue : newValues) {
			if (allValues.contains(newValue)) {
				log.debug("Ignoring duplicate claim={} value={}", oidcName, newValue);
			}
			else {
				allValues.add(newValue);
			}
		}
		return allValues;
	}

	// check if AttributeRegistry provides a standard OIDC claim name
	private static AttributeName getOidcStandardClaimName(Definition definition) {
		var attributeName = definition.findAttributeName();
		if (attributeName != null && !CollectionUtils.isEmpty(attributeName.getOidcNameList())) {
			return attributeName;
		}
		return null;
	}

	public static void addListClaimToContext(JwtEncodingContext context, String name, List<?> values) {
		if (values != null && !values.isEmpty()) {
			context.getClaims().claim(name, values);
		}
	}

	public static void addSingledValueListAsStringToClaim(JwtEncodingContext context, String name, List<?> values) {
		if (values != null && !values.isEmpty()) {
			if (values.size() > 1) {
				log.warn("Cannot convert Claim={} with multiple values to String claim", name);
			}
			context.getClaims().claim(name, values.get(0));
		}
	}

	static void removeDisabledEndpointFromMetadataClaim(OidcProperties oidcProperties, Map<String, Object> claimMap) {
		if (!oidcProperties.isIntrospectionEnabled()) {
			claimMap.remove(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT);
			claimMap.remove(
					OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED);
		}
		if (!oidcProperties.isRevocationEnabled()) {
			claimMap.remove(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT);
			claimMap.remove(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED);
		}
		if (!oidcProperties.isUserInfoEnabled()) {
			claimMap.remove(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT);
		}
		if (!oidcProperties.isDeviceAuthorizationEnabled()) {
			claimMap.remove(OAuth2AuthorizationServerMetadataClaimNames.DEVICE_AUTHORIZATION_ENDPOINT);
		}
		if (!oidcProperties.isPushedAuthorizationRequestsEndpointEnabled()) {
			claimMap.remove(OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT);
		}
		if (CollectionUtils.isEmpty(oidcProperties.getDPoPSigningAlgValuesSupported())) {
			claimMap.remove(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED);
		}
		// authorization, token, and JWKS endpoints are always required
	}

	static String computeEndSessionEndpoint(OidcProperties oidcProperties) {
		var endSessionEndpoint = oidcProperties.getEndSessionEndpoint();
		if (endSessionEndpoint == null) {
			var baseUrl = oidcProperties.getIssuer();
			var sep = baseUrl.endsWith("/") ? "" : "/";
			endSessionEndpoint = oidcProperties.getIssuer() + sep + "logout";
		}

		return endSessionEndpoint;
	}

	static void setEndSessionEndpoint(OidcProperties oidcProperties,
			OidcProviderConfiguration.Builder providerConfiguration) {
		String finalEndSessionEndpoint = computeEndSessionEndpoint(oidcProperties);
		addClaimToProviderConfiguration(providerConfiguration,
				OidcProviderMetadataClaimNames.END_SESSION_ENDPOINT, finalEndSessionEndpoint);
	}

	public static void addOptionalClaimToProviderConfiguration(OidcProviderConfiguration.Builder providerConfiguration,
			String claimName, Object claimValue) {
		if (claimValue != null) {
			addClaimToProviderConfiguration(providerConfiguration, claimName, claimValue);
		}
	}

	public static void addClaimToProviderConfiguration(OidcProviderConfiguration.Builder providerConfiguration,
			String claimName, Object claimValue) {
		providerConfiguration
				.claim(claimName, claimValue)
				.build();
	}

	static boolean isRedirectUrlValid(String redirectUrl, String clientId, String redirectUrlParameterName,
			RelyingPartyDefinitions relyingPartyDefinitions, ClientConfigInMemoryRepository registeredClientRepository) {
		var ok = false;
		Set<String> configuredRedirectUrls = null;

		// Get XTB client configuration
		// We use regexp matching on path here
		if (clientId == null) {
			var client = relyingPartyDefinitions.getOidcClientByPredicate(cl -> cl.isValidRedirectUri(redirectUrl));
			clientId = client.map(OidcClient::getId).orElse(null);
		}

		// get spring-sec client information
		var registeredClient = registeredClientRepository.findByClientId(clientId);
		if (registeredClient != null) {
			ok = UrlAcceptor.isRedirectUrlOkForAccess(redirectUrl, registeredClient.getRedirectUris());
			configuredRedirectUrls = registeredClient.getRedirectUris();
		}
		if (ok) {
			log.debug("{}={} for client_id={} is one of the allowed uris={}",
					redirectUrlParameterName, redirectUrl, clientId, configuredRedirectUrls);
		}
		else {
			log.error("{}={} for client_id={} is not one of the allowed uris={}",
					redirectUrlParameterName, redirectUrl, clientId, configuredRedirectUrls);
		}
		return ok;
	}

	// always have a protected secret to handle IllegalArgumentException from DelegatingPasswordEncoder.NO_PASSWORD_ENCODER_PREFIX
	private static String completeSecret(String secret) {
		return secret != null ? secret : "{sha256}" + DigestUtils.sha256Hex(UUID.randomUUID().toString().getBytes());
	}

}
