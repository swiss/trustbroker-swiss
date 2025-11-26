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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CoreAttributeInitializer;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.AuthorizationGrantType;
import swiss.trustbroker.federation.xmlconfig.AuthorizationGrantTypes;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethod;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethods;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Multivalued;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.OidcSecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.Scope;
import swiss.trustbroker.federation.xmlconfig.Scopes;
import swiss.trustbroker.oidc.session.OidcSessionSupport;

@SpringBootTest(classes = OidcConfigurationUtilTest.class)
class OidcConfigurationUtilTest {

	private static final List<String> ROLES = List.of("APP1.ALLOW", "APP2.ALLOW", "APP2.ROLE1");

	private static final String CLAIMS_NAME_ATTRIBUTE = "claims";

	private static final String FIRST_NAME_ATTRIBUTE = "fname";

	private static final String LAST_NAME_ATTRIBUTE = "lname";

	public static final List<Object> FIRST_NAMES = List.of("first1", "first2");

	public static final List<Object> CLAIMS_NAMES = List.of("claim\\1", "claim\\2");

	private static final int DEFAULT_TOKEN_TIME_SECS = 120;

	private static final int DEFAULT_CODE_TIME_SECS = 60;

	private static final int ACCESS_TOKEN_TIME_TO_LIVE_MIN = 4;

	private static final int REFRESH_TOKEN_TIME_TO_LIVE_MIN = 5;

	private static final int AUTHORIZATION_CODE_TIME_TO_LIVE_MIN = DEFAULT_CODE_TIME_SECS / 60;

	@BeforeAll
	static void setup() {
		new CoreAttributeInitializer().init();
	}

	@Test
	void addValueToAttributeTest() {
		var claimMap = givenClaimMap();

		// add new attribute
		addValueToListClaim(claimMap, "homename", List.of("homename"), Multivalued.LIST);

		// add the same value for the same claim -> no duplicate
		addValueToListClaim(claimMap, "homename", List.of("homename"), Multivalued.LIST);

		// "name" claim is already in the map
		addMultiValueToClaim(claimMap, "name", List.of("newName"), Multivalued.ORIGINAL);

		// "loginid" claim is already in the map but multiValued=false -> must overwrite the existing value
		addValueToListClaim(claimMap, "loginid", List.of("ch1242"), Multivalued.LIST);

		// role (aggregate)
		addMultiValueToClaim(claimMap, "role", List.of("newRole", ROLES.get(1)), Multivalued.ORIGINAL);
		var attrRoles = (List<?>) claimMap.get("role");
		assertThat(attrRoles, containsInAnyOrder("newRole", ROLES.get(0), ROLES.get(1), ROLES.get(2)));
		// role (override)
		addMultiValueToClaim(claimMap, "role", List.of("newRole2", "newRole3"), Multivalued.ORIGINAL);
		assertTrue(((List<?>) claimMap.get("role")).contains("newRole2"));
		assertTrue(((List<?>) claimMap.get("role")).contains("newRole2"));

		// add String values
		addSingleValue(claimMap, "customElement1", List.of("en"), Multivalued.STRING);
		addSingleValue(claimMap, "customElement2", List.of("elem1", "elem2"), Multivalued.STRING);

		// multiValued = ERROR
		addSingeValueOrError(claimMap, "customElement3", List.of("elem1", "elem2"), Multivalued.ERROR, true);
		addSingeValueOrError(claimMap, "customElement4", List.of("elem1"), Multivalued.ERROR, false);

		// standard claim flag
		addStandardClaim(claimMap, "customElement5", List.of("elem1", "elem2"), Multivalued.STRING);
	}

	@Test
	void getOidcAttributeValuesTest() {
		var attributes = givenClaimMap();

		var noValues = OidcConfigurationUtil.getOidcAttributeValues(attributes, "attributeNotInMap", List.of("value"));
		assertEquals(1, noValues.size());

		var stringValue = OidcConfigurationUtil.getOidcAttributeValues(attributes, "name", List.of("value"));
		assertEquals(2, stringValue.size());

		var listValue = OidcConfigurationUtil.getOidcAttributeValues(attributes, "email", List.of("value"));
		assertEquals(3, listValue.size());

		// de-duplication test
		var dedupListValue = OidcConfigurationUtil.getOidcAttributeValues(attributes, "role", List.of("value", ROLES.get(0)));
		assertEquals(4, dedupListValue.size());
		assertThat(dedupListValue, containsInAnyOrder("value", ROLES.get(0), ROLES.get(1), ROLES.get(2)));
	}

	@Test
	void getStringValueOfOidcClaimTest() {
		List<Object> values = List.of("elem1");
		assertEquals("elem1", OidcConfigurationUtil.getStringValueOfOidcClaim(values));

		values = List.of("elem1", "elem2");
		assertEquals(StringUtils.join(values, " "), OidcConfigurationUtil.getStringValueOfOidcClaim(values));

		values = List.of("elem1", "{\"mrole\":[\"mrole1\",\"mrole2\"]}");
		assertEquals(StringUtils.join(values, " "), OidcConfigurationUtil.getStringValueOfOidcClaim(values));

		var jsonSubTree = new HashMap<>();
		jsonSubTree.put("epoch1970", Instant.parse("1970-01-01T23:59:59Z").getEpochSecond());
		jsonSubTree.put("num2023", 2023);
		values = List.of("elem1", jsonSubTree);
		assertEquals(StringUtils.join(values, " "), OidcConfigurationUtil.getStringValueOfOidcClaim(values));
	}

	private static void addMultiValueToClaim(Map<String, Object> claimMap, String oidcName, List<Object> values,
			Multivalued multivalued) {
		var def = Definition.builder().oidcNames(oidcName).multiValued(multivalued).build();
		OidcConfigurationUtil.addClaimsToMap(claimMap, def, values, "oidcClientId", false);
		assertTrue(claimMap.containsKey(oidcName));
		var attrValues = claimMap.get(oidcName);
		assertTrue(attrValues instanceof List<?>);
		values.forEach(v -> assertTrue(((List<?>) attrValues).contains(v)));
	}

	private static void addValueToListClaim(Map<String, Object> claimMap,
			String oidcNames, List<Object> values, Multivalued multivalued) {
		var def = Definition.builder().oidcNames(oidcNames).multiValued(multivalued).build();
		OidcConfigurationUtil.addClaimsToMap(claimMap, def, values, "oidcClientId", false);
		assertTrue(claimMap.containsKey(oidcNames));
		assertTrue(claimMap.get(oidcNames) instanceof List<?>);
		assertTrue(((List<?>) claimMap.get(oidcNames)).contains(values.get(0)));
	}

	private void addSingleValue(Map<String, Object> claimMap, String oidcNames, List<Object> values, Multivalued multivalued) {
		var def = Definition.builder().oidcNames(oidcNames).multiValued(multivalued).build();
		OidcConfigurationUtil.addClaimsToMap(claimMap, def, values, "oidcClientId", false);
		assertTrue(claimMap.containsKey(oidcNames));
		assertTrue(claimMap.get(oidcNames) instanceof String);
		assertEquals(StringUtils.join(values, " "), claimMap.get(oidcNames));
	}

	private void addStandardClaim(Map<String, Object> claimMap, String oidcNames, List<Object> values, Multivalued multivalued) {
		var def = Definition.builder().oidcNames(oidcNames).multiValued(multivalued).build();
		OidcConfigurationUtil.addClaimsToMap(claimMap, def, values, "oidcClientId", true);
		assertTrue(claimMap.containsKey(oidcNames));
		assertTrue(claimMap.get(oidcNames) instanceof List<?>);
		assertTrue(((List<?>) claimMap.get(oidcNames)).contains(values.get(0)));
	}

	private void addSingeValueOrError(Map<String, Object> claimMap, String oidcNames, List<Object> values,
			Multivalued multivalued, boolean throwException) {
		var def = Definition.builder().oidcNames(oidcNames).multiValued(multivalued).build();

		if (throwException) {
			assertThrows(TechnicalException.class,
					() -> OidcConfigurationUtil.addClaimsToMap(claimMap, def, values, "oidcClientId", false));
		}
		else {
			OidcConfigurationUtil.addClaimsToMap(claimMap, def, values, "oidcClientId", false);
			assertTrue(claimMap.containsKey(oidcNames));
			assertTrue(claimMap.get(oidcNames) instanceof String);
			assertEquals(StringUtils.join(values, " "), claimMap.get(oidcNames));
		}
	}

	private Map<String, Object> givenClaimMap() {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put("name", "TestName");
		attributes.put("email", List.of("testNameEmail", "email"));
		attributes.put("loginid", "ch12312");
		attributes.put("language", List.of("en", "de"));
		attributes.put("role", ROLES);
		return attributes;
	}

	@Test
	void removeDisabledEndpointFromMetadataClaimTest() {
		OidcProperties oidcProperties = givenOidcProperties(false, true, true);
		Map<String, Object> metadataClaimMap = givenMetadataClaimMap();

		OidcConfigurationUtil.removeDisabledEndpointFromMetadataClaim(oidcProperties, metadataClaimMap);
		assertNull(metadataClaimMap.get(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT));
		assertNull(
				metadataClaimMap.get(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED));
		assertNotNull(metadataClaimMap.get(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT));
		assertNotNull(
				metadataClaimMap.get(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED));
		assertNotNull(metadataClaimMap.get(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT));


		oidcProperties = givenOidcProperties(true, false, false);
		metadataClaimMap = givenMetadataClaimMap();

		OidcConfigurationUtil.removeDisabledEndpointFromMetadataClaim(oidcProperties, metadataClaimMap);
		assertNotNull(metadataClaimMap.get(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT));
		assertNotNull(
				metadataClaimMap.get(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED));
		assertNull(metadataClaimMap.get(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT));
		assertNull(metadataClaimMap.get(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED));
		assertNull(metadataClaimMap.get(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT));
	}

	@Test
	void computeEndSessionEndpointTest() {
		OidcProperties oidcProperties = givenOidcProperties(true, true, true);

		String endSessionEndpoint = OidcConfigurationUtil.computeEndSessionEndpoint(oidcProperties);
		assertThat(endSessionEndpoint, is("http://localhost/logout"));
	}

	@Test
	void setEndSessionEndpointTest() {
		OidcProperties oidcProperties = givenOidcProperties(true, true, true);
		OidcProviderConfiguration.Builder oidcProviderBuilder = OidcProviderConfiguration.withClaims(givenProviderClaimMap());

		OidcConfigurationUtil.setEndSessionEndpoint(oidcProperties, oidcProviderBuilder);
		assertTrue(oidcProviderBuilder.build().hasClaim("end_session_endpoint"));
	}

	@Test
	void testComputeOidcClaims() {
		var attributesFromContext = givenSamlAttributes();
		var definitions = givenDefinitions();
		var mapped = OidcConfigurationUtil.computeOidcClaims(attributesFromContext, definitions, null, false, null);
		assertThat(mapped, is(notNullValue()));
		var sessions = mapped.get(CLAIMS_NAME_ATTRIBUTE);
		assertThat(sessions, is(notNullValue()));
		assertThat(sessions, is(CLAIMS_NAMES));
		var firstNames = mapped.get(FIRST_NAME_ATTRIBUTE);
		assertThat(firstNames, is(notNullValue()));
		assertThat(firstNames, is(FIRST_NAMES));
		var lastNames = mapped.get(LAST_NAME_ATTRIBUTE);
		assertThat(lastNames, is(notNullValue()));
		assertThat(firstNames, is(FIRST_NAMES));
	}

	@Test
	void testGetTokenSettings() {
		var noSettings = OidcConfigurationUtil.getTokenSettings(null, 1800, 300); // sessionLifetimeSec
		assertThat(noSettings.getAuthorizationCodeTimeToLive(), is(Duration.ofMinutes(5)));
		assertThat(noSettings.getAccessTokenTimeToLive(), is(Duration.ofMinutes(30)));
		assertThat(noSettings.getRefreshTokenTimeToLive(), is(Duration.ofMinutes(30)));

		var defaultSettings = OidcConfigurationUtil.getTokenSettings(
				OidcConfigurationUtil.defaultSecurityPolicies(180), 180, 120);
		assertThat(defaultSettings.getAuthorizationCodeTimeToLive(), is(Duration.ofMinutes(2)));
		assertThat(defaultSettings.getAccessTokenTimeToLive(), is(Duration.ofMinutes(3)));
		assertThat(defaultSettings.getRefreshTokenTimeToLive(), is(Duration.ofMinutes(3)));

		var maxAgeSec = 725 * 60;
		var pkcePolicies = OidcSecurityPolicies.builder()
				.authorizationCodeTimeToLiveMin(115)
				.tokenTimeToLiveMin(125)
				.sessionTimeToLiveMin(maxAgeSec / 60)
				.build();
		var pkceSettings = OidcConfigurationUtil.getTokenSettings(pkcePolicies, 1800, 6);
		assertThat(pkceSettings.getAuthorizationCodeTimeToLive(), is(Duration.ofMinutes(115)));
		assertThat(pkceSettings.getAccessTokenTimeToLive(), is(Duration.ofMinutes(125)));
		assertThat(pkceSettings.getRefreshTokenTimeToLive(), is(Duration.ofMinutes(30))); // unused

		// adapters like keycloak.js require the code to be valid multiple times over the login period
		var clientId = "BSESSION_CLIENT_ID";
		var sessionId = "test";
		var sameSite = "LAX";
		var cookie = OidcSessionSupport.createOidcClientCookie(clientId,
				sessionId, pkcePolicies.getSessionTimeToLiveMin() * 60, true, sameSite);
		assertThat(cookie.getMaxAge(), is(maxAgeSec));
		assertThat(cookie.getName(), is(clientId));
		assertThat(cookie.getValue(), is(sessionId));
		assertThat(cookie.getSecure(), is(true));
		assertThat(cookie.getAttribute(WebUtil.COOKIE_SAME_SITE), is(sameSite));

		var privPolicies = OidcSecurityPolicies.builder()
				.tokenTimeToLiveMin(125)
				.refreshTokenTimeToLiveMin(135)
				.build();
		var privSettings = OidcConfigurationUtil.getTokenSettings(privPolicies, 1800, 300);
		assertThat(privSettings.getAuthorizationCodeTimeToLive(), is(Duration.ofMinutes(5)));
		assertThat(privSettings.getAccessTokenTimeToLive(), is(Duration.ofMinutes(125)));
		assertThat(privSettings.getRefreshTokenTimeToLive(), is(Duration.ofMinutes(135)));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"3600,60,null,null,null,null,null,1,null,60,60", // fallback to global token TTL (in seconds)
			"3600,60,null,120,null,null,null,1,120,120,60", // fallback to tokenTtl
			"3600,60,3,160,170,180,190,3,170,180,190", // override tokenTtl
			"900,120,null,null,239,240,241,2,239,240,241", // no tokenTtl
	}, nullValues = "null")
	void testGetTokenSettingsOverride(
			Integer globalTokenTtlSecs, Integer globalCodeTtlSecs,
			Integer codeTtl, Integer tokenTtl, Integer idTokenTtl, Integer accessTokenTtl, Integer refreshTokenTtl,
			Integer expectedCodeTtl, Integer expectedIdTokenTtl, Integer expectedAccessTokenTtl,
			Integer expectedRefreshTokenTtl) {
		var policies = OidcSecurityPolicies.builder()
				.tokenTimeToLiveMin(tokenTtl)
				.idTokenTimeToLiveMin(idTokenTtl)  // workaround in OidcSecurityConfiguration.setExpClaim
				.accessTokenTimeToLiveMin(accessTokenTtl)
				.refreshTokenTimeToLiveMin(refreshTokenTtl)
				.authorizationCodeTimeToLiveMin(codeTtl)
				.build();
		assertThat(policies.getIdTokenTimeToLiveMin(), is(expectedIdTokenTtl)); // defaultTokenTimeMin has no effect
		var settings = OidcConfigurationUtil.getTokenSettings(policies, globalTokenTtlSecs, globalCodeTtlSecs);
		assertThat(settings.getAuthorizationCodeTimeToLive(), is(Duration.ofMinutes(expectedCodeTtl)));
		assertThat(settings.getAccessTokenTimeToLive(), is(Duration.ofMinutes(expectedAccessTokenTtl)));
		assertThat(settings.getRefreshTokenTimeToLive(), is(Duration.ofMinutes(expectedRefreshTokenTtl)));
	}

	@Test
	void deduplicateOriginalIssuerDuplicates() {
		Map<String, List<Object>> attributes = givenAttributesWithDuplicates();
		OidcConfigurationUtil.deduplicateOriginalIssuerDuplicates(attributes);
		assertEquals(1, attributes.get(CoreAttributeName.CLAIMS_NAME.getNamespaceUri()).size());
		assertEquals(1, attributes.get(CoreAttributeName.NAME.getNamespaceUri()).size());
		assertFalse(attributes.get(CoreAttributeName.NAME.getNamespaceUri()) instanceof ImmutableList<Object>);
	}

	@ParameterizedTest
	@CsvSource(value = { "false", "true" })
	void createRegisteredClient(boolean withDefaults) {
		var oidcClient = givenOidcClient(withDefaults);

		var result = OidcConfigurationUtil.createRegisteredClient(oidcClient, DEFAULT_TOKEN_TIME_SECS, DEFAULT_CODE_TIME_SECS);

		var authMethods = ClientAuthenticationMethod.defaultValues();
		var grantTypes = AuthorizationGrantType.defaultValues();
		var scopes = Scope.defaultNames();
		if (!withDefaults) {
			authMethods = oidcClient.getClientAuthenticationMethods().getMethods();
			grantTypes = oidcClient.getAuthorizationGrantTypes().getGrantTypes();
			scopes = oidcClient.getScopes().getScopeList();
		}
		var authMethodsArray = authMethods.stream().map(ClientAuthenticationMethod::getMethod).toArray(Object[]::new);
		var grantTypesArray = grantTypes.stream().map(AuthorizationGrantType::getType).toArray(Object[]::new);
		var scopesArray = scopes.toArray(Object[]::new);

		assertThat(oidcClient.getRegisteredClient(), is(result));
		assertThat(result.getId(), is(oidcClient.getId()));
		assertThat(result.getClientId(), is(oidcClient.getId()));
		assertThat(result.getClientSecret(), is(oidcClient.getClientSecret()));
		assertThat(result.getClientSettings(), is(givenClientSettings()));
		assertThat(result.getClientAuthenticationMethods(), containsInAnyOrder(authMethodsArray));
		assertThat(result.getAuthorizationGrantTypes(), containsInAnyOrder(grantTypesArray));
		assertThat(result.getScopes(), containsInAnyOrder(scopesArray));
		var redirectUris = oidcClient.getRedirectUris().getRedirectUrls().toArray(Object[]::new);
		assertThat(result.getRedirectUris(), containsInAnyOrder(redirectUris));
		assertThat(result.getTokenSettings(), is(givenTokenSettings()));
	}

	private static OidcClient givenOidcClient(boolean withDefaults) {
		var builder = OidcClient.builder()
				.id("client1")
				.clientSecret("secret1")
				.redirectUris(AcWhitelist.builder()
						.acUrls(List.of("https://localhost/test"))
						.build())
				.oidcSecurityPolicies(OidcSecurityPolicies.builder()
						.requireProofKey(true)
						.requireAuthorizationConsent(true)
						.reuseRefreshTokens(true)
						.accessTokenTimeToLiveMin(ACCESS_TOKEN_TIME_TO_LIVE_MIN)
						.refreshTokenTimeToLiveMin(REFRESH_TOKEN_TIME_TO_LIVE_MIN)
						.authorizationCodeTimeToLiveMin(AUTHORIZATION_CODE_TIME_TO_LIVE_MIN)
						.idTokenSignature(SignatureAlgorithm.RS256.getName())
						.build());
		if (!withDefaults) {
					builder.clientAuthenticationMethods(ClientAuthenticationMethods.builder()
						.methods(List.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
								ClientAuthenticationMethod.CLIENT_SECRET_POST)).build())
					.authorizationGrantTypes(AuthorizationGrantTypes.builder()
						.grantTypes(
								List.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN)).build())
					.scopes(Scopes.builder()
						.scopeList(List.of(Scope.ADDRESS.getName(), Scope.OPENID.getName())).build());
		}
		return builder.build();
	}

	private static ClientSettings givenClientSettings() {
		return ClientSettings.builder()
				.requireProofKey(true)
				.requireAuthorizationConsent(true)
				.build();
	}

	private static TokenSettings givenTokenSettings() {
		return TokenSettings.builder()
				.reuseRefreshTokens(true)
				.accessTokenTimeToLive(Duration.ofMinutes(ACCESS_TOKEN_TIME_TO_LIVE_MIN))
				.refreshTokenTimeToLive(Duration.ofMinutes(REFRESH_TOKEN_TIME_TO_LIVE_MIN))
				.authorizationCodeTimeToLive(Duration.ofMinutes(AUTHORIZATION_CODE_TIME_TO_LIVE_MIN))
				.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
				.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
				.build();
	}

	private Map<String, List<Object>> givenAttributesWithDuplicates() {
		var map = new HashMap<String, List<Object>>();
		map.put(CoreAttributeName.EMAIL.getNamespaceUri(), new ArrayList<>(Arrays.asList("email1", "email2")));
		map.put(CoreAttributeName.CLAIMS_NAME.getNamespaceUri(), new ArrayList<>(Arrays.asList("claim", "claim")));
		map.put(CoreAttributeName.NAME.getNamespaceUri(), new ArrayList<>(Arrays.asList("name", "name")));
		map.put(CoreAttributeName.FIRST_NAME.getNamespaceUri(), new ArrayList<>(Arrays.asList("1", "2")));
		return map;
	}

	private static Map<String, List<Object>> givenSamlAttributes() {
		return Map.of(
				CoreAttributeName.CLAIMS_NAME.getNamespaceUri(), CLAIMS_NAMES,
				CoreAttributeName.FIRST_NAME.getNamespaceUri(), FIRST_NAMES
		);
	}

	private static List<Definition> givenDefinitions() {
		return List.of(
				Definition.builder().name(CoreAttributeName.FIRST_NAME.getName())
						  .namespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri())
						  .oidcNames(FIRST_NAME_ATTRIBUTE).build(),
				Definition.builder().name(CoreAttributeName.CLAIMS_NAME.getName())
						  .namespaceUri(CoreAttributeName.CLAIMS_NAME.getNamespaceUri())
						  .oidcNames(CLAIMS_NAME_ATTRIBUTE).build(),
				Definition.builder().name(CoreAttributeName.NAME.getName())
						  .namespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri()) // simulate duplicate
						  .oidcNames(LAST_NAME_ATTRIBUTE).build()
		);
	}

	private static OidcProperties givenOidcProperties(boolean introspectionEnabled, boolean revocationEnabled,
			boolean userinfoEnabled) {
		var properties = new OidcProperties();
		properties.setIssuer("http://localhost/");
		properties.setIntrospectionEnabled(introspectionEnabled);
		properties.setRevocationEnabled(revocationEnabled);
		properties.setUserInfoEnabled(userinfoEnabled);
		return properties;
	}

	private Map<String, Object> givenMetadataClaimMap() {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT, "any");
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED, "any");
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT, "any");
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED, "any");
		attributes.put(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT, "any");
		return attributes;
	}

	private Map<String, Object> givenProviderClaimMap() {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT, "http://localhost/");
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED, List.of("any"
		));
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT, "http://localhost/");
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED, List.of("any"));
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, "http://localhost/");
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, "http://localhost/");
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, List.of("any"));
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI, "http://localhost/");
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT, "http://localhost/");
		attributes.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, List.of("any"));
		attributes.put(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, List.of("any"));
		attributes.put(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED, List.of("any"));
		attributes.put(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT, "http://localhost/");
		return attributes;
	}

}
