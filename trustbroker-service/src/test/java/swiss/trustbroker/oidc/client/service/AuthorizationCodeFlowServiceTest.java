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

package swiss.trustbroker.oidc.client.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.OidcClaimsSource;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.federation.xmlconfig.ResponseMode;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.mapping.dto.QoaSpec;
import swiss.trustbroker.oidc.OidcMockTestData;
import swiss.trustbroker.oidc.cache.service.OidcMetadataCacheService;
import swiss.trustbroker.oidc.client.dto.OpenIdProviderConfiguration;
import swiss.trustbroker.util.ApiSupport;

@SpringBootTest(classes = AuthorizationCodeFlowService.class)
class AuthorizationCodeFlowServiceTest {

	@MockitoBean
	private ApiSupport apiSupport;

	@MockitoBean
	private OidcMetadataCacheService oidcMetadataCacheService;

	@MockitoBean
	private OidcTokenService oidcTokenService;

	@MockitoBean
	private OidcUserinfoService oidcUserinfoService;

	@MockitoBean
	private JwtClaimsService jwtClaimsService;

	@MockitoBean
	private OidcClaimValidatorService oidcClaimValidatorService;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@Autowired
	private AuthorizationCodeFlowService authorizationCodeFlowService;

	@BeforeEach
	void setUp() {
		var securityChecks = new SecurityChecks();
		when(trustBrokerProperties.getSecurity()).thenReturn(securityChecks);
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,false,false,null,'',null",
			"null,null,true,null,&prompt=login,null", // CP default true
			"true,null,true,QUERY,&prompt=login,null",
			"true,null,true,QUERY,&prompt=login,null,claims=%7B%22id_token%22%3A%7B%22acr%22%3A+%7B%22essential%22%3A+true%2C%22values%22%3A+%5B%22acrvalue%22%5D%7D%7D%7D",
			"null,true,true,null,&prompt=login,null"
	}, nullValues = "null")
	void createAuthnRequest(Boolean stateForceAuthn, Boolean cpForceAuthn, Boolean resultForceAuthn,
							ResponseMode responseMode, String prompt, String queryParam) {
		var client = OidcMockTestData.givenClient();
		var expectedResponseMode = ResponseMode.FORM_POST.getName();
		if (responseMode != null) {
			client.setResponseMode(responseMode);
			expectedResponseMode = responseMode.getName();
		}
		var cp = OidcMockTestData.givenCpWithOidcClient(client);
		if (cpForceAuthn != null) {
			cp.setSecurityPolicies(SecurityPolicies.builder().forceAuthn(cpForceAuthn).build());
		}
		var state = OidcMockTestData.givenStateData();
		state.setForceAuthn(stateForceAuthn);
		var configuration = OidcMockTestData.givenConfiguration();
		mockServiceResults(configuration, cp);
		var acrValues = List.of("acr1", "acr2");
		var qoaSpec = new QoaSpec(QoaComparison.EXACT, acrValues);

		var result = authorizationCodeFlowService.createAuthnRequest(cp, state, qoaSpec, queryParam);

		assertThat(result.clientId(), is(OidcMockTestData.CLIENT_ID));
		assertThat(result.acrValues(), is(acrValues));
		assertThat(result.scopes(), is(List.of("openid", "profile", "email", "address", "phone")));
		assertThat(result.forceAuthn(), is(resultForceAuthn));
		assertThat(result.destination(), is(OidcMockTestData.AUTHORIZE_ENDPOINT));
		assertThat(result.assertionConsumerUrl(), is(OidcMockTestData.REDIRECT_URI));
		if (queryParam != null) {
			assertThat(result.requestUri(), is(OidcMockTestData.AUTHORIZE_ENDPOINT +
					"?response_type=code"
					+ "&response_mode=" + expectedResponseMode
					+ "&client_id=" + OidcMockTestData.CLIENT_ID
					+ "&state=" + OidcMockTestData.SP_SESSION_ID
					+ "&scope=openid+profile+email+address+phone"
					+ "&nonce=" + OidcMockTestData.NONCE
					+ "&redirect_uri=" + OidcMockTestData.REDIRECT_URI_ENCODED
					+ "&claims=" + OidcMockTestData.CUSTOM_PARAM_ENCODED));
		}
		else {
			assertThat(result.requestUri(), is(OidcMockTestData.AUTHORIZE_ENDPOINT +
					"?response_type=code"
					+ "&response_mode=" + expectedResponseMode
					+ "&client_id=" + OidcMockTestData.CLIENT_ID
					+ "&state=" + OidcMockTestData.SP_SESSION_ID
					+ "&scope=openid+profile+email+address+phone"
					+ "&nonce=" + OidcMockTestData.NONCE
					+ "&redirect_uri=" + OidcMockTestData.REDIRECT_URI_ENCODED
					+ prompt
					+ "&acr_values=acr1+acr2"));
		}
	}

	@Test
	void handleCpResponse() {
		var client = OidcMockTestData.givenClient();
		var cp = OidcMockTestData.givenCpWithOidcClient(client);
		var configuration = OidcMockTestData.givenConfiguration();
		mockServiceResults(configuration, cp);
		doReturn(Map.of(OidcUtil.TOKEN_RESPONSE_ID_TOKEN, OidcMockTestData.ID_TOKEN,
				OidcUtil.TOKEN_RESPONSE_ACCESS_TOKEN, OidcMockTestData.ACCESS_TOKEN))
				.when(oidcTokenService)
				.fetchTokens(client, cp.getCertificates(), configuration, OidcMockTestData.REDIRECT_URI, OidcMockTestData.CODE);
		var key = OidcMockTestData.givenJwk(OidcMockTestData.KEY_ID);
		doReturn(key).when(oidcMetadataCacheService).getKey(cp, OidcMockTestData.KEY_ID);
		var stateData = OidcMockTestData.givenStateData();
		var userInfoClaims = OidcUtil.parseJwtClaims(OidcMockTestData.USERINFO_RESPONSE);
		doReturn(userInfoClaims)
				.when(oidcUserinfoService)
				.fetchUserInfo(eq(client), eq(cp.getCertificates()), eq(configuration), eq(OidcMockTestData.ACCESS_TOKEN), any());
		var contextClasses = List.of("ctx1");
		doReturn(contextClasses).when(jwtClaimsService).getCtxClasses(any(), eq(cp));
		var attributes = Map.of(new Definition(OidcMockTestData.CLAIM_EMAIL), List.of(OidcMockTestData.EMAIL),
				new Definition(OidcMockTestData.GIVEN_NAME), List.of(OidcMockTestData.GIVEN_NAME),
				new Definition(OidcMockTestData.FAMILY_NAME), List.of(OidcMockTestData.FAMILY_NAME));
		doReturn(attributes).when(jwtClaimsService).mapClaimsToAttributes(any(), eq(cp));

		var cpResponse = authorizationCodeFlowService.handleCpResponse(
				OidcMockTestData.REALM, OidcMockTestData.CODE, cp, stateData);

		verify(oidcClaimValidatorService).validateClaims(
				any(), eq(cp), eq(client), eq(configuration.getIssuerId()), eq(OidcMockTestData.NONCE));
		assertThat(cpResponse, is(not(nullValue())));
		assertThat(cpResponse.getIssuer(), is(OidcMockTestData.CP_ISSUER_ID));
		assertThat(cpResponse.getOidcClientId(), is(OidcMockTestData.CLIENT_ID));
		assertThat(cpResponse.getNameId(), is(OidcMockTestData.SUBJECT));
		assertThat(cpResponse.getHomeName(), is(OidcMockTestData.CP_HOME_NAME));
		assertThat(cpResponse.getContextClasses(), is(contextClasses));
		assertThat(cpResponse.getClaims().size(), is(OidcMockTestData.ID_TOKEN_CLAIMS));
		assertThat(cpResponse.getClaim(OidcUtil.OIDC_SUBJECT), is(OidcMockTestData.SUBJECT));
		assertThat(cpResponse.getClaim(OidcMockTestData.CLAIM_GIVEN_NAME), is(OidcMockTestData.GIVEN_NAME));
		assertThat(cpResponse.getAttributes().size(), is(attributes.size()));
		assertThat(cpResponse.getAttribute(OidcMockTestData.CLAIM_EMAIL), is(OidcMockTestData.EMAIL));
	}

	@ParameterizedTest
	@MethodSource
	void mergeClaims(List<OidcClaimsSource> sources, Map<String, Object> idTokenClaims,
					 Map<String, Object> userinfoClaims, Map<String, Object> expectedClaims) throws Exception {
		var client = OidcMockTestData.givenClient();
		client.getClaimsSources().setClaimsSourceList(sources);
		var tokenClaims = JWTClaimsSet.parse(idTokenClaims);
		var infoClaims = JWTClaimsSet.parse(userinfoClaims);
		var claims = AuthorizationCodeFlowService.mergeClaims(client, tokenClaims, infoClaims);
		assertThat(claims, is(not(nullValue())));
		assertThat(claims.toJSONObject(), is(expectedClaims));
	}

	static Object[][] mergeClaims() {
		var tokenEmail = "token" + OidcMockTestData.EMAIL;
		var idTokenClaims = Map.of(
				OidcUtil.OIDC_SUBJECT, OidcMockTestData.SUBJECT,
				OidcUtil.OIDC_ISSUER, OidcMockTestData.CP_ISSUER_ID,
				OidcMockTestData.CLAIM_EMAIL, tokenEmail // simulate conflict
		);
		var userinfoClaims = Map.of(
				OidcMockTestData.CLAIM_GIVEN_NAME, OidcMockTestData.GIVEN_NAME,
				OidcMockTestData.CLAIM_FAMILY_NAME, OidcMockTestData.FAMILY_NAME,
				OidcMockTestData.CLAIM_EMAIL, OidcMockTestData.EMAIL
		);
		return new Object[][]{
				{List.of(OidcClaimsSource.ID_TOKEN), idTokenClaims, userinfoClaims, idTokenClaims},
				{List.of(OidcClaimsSource.USERINFO), idTokenClaims, userinfoClaims, userinfoClaims},
				{List.of(OidcClaimsSource.ID_TOKEN, OidcClaimsSource.USERINFO), idTokenClaims, userinfoClaims,
						Map.of(
								// ID_TOKEN
								OidcUtil.OIDC_SUBJECT, OidcMockTestData.SUBJECT,
								OidcUtil.OIDC_ISSUER, OidcMockTestData.CP_ISSUER_ID,
								OidcMockTestData.CLAIM_EMAIL, tokenEmail,
								// USERINFO
								OidcMockTestData.CLAIM_GIVEN_NAME, OidcMockTestData.GIVEN_NAME,
								OidcMockTestData.CLAIM_FAMILY_NAME, OidcMockTestData.FAMILY_NAME
						)},
				{List.of(OidcClaimsSource.USERINFO, OidcClaimsSource.ID_TOKEN), idTokenClaims, userinfoClaims,
						Map.of(
								// USERINFO
								OidcMockTestData.CLAIM_GIVEN_NAME, OidcMockTestData.GIVEN_NAME,
								OidcMockTestData.CLAIM_FAMILY_NAME, OidcMockTestData.FAMILY_NAME,
								OidcMockTestData.CLAIM_EMAIL, OidcMockTestData.EMAIL,
								// ID_TOKEN
								OidcUtil.OIDC_SUBJECT, OidcMockTestData.SUBJECT,
								OidcUtil.OIDC_ISSUER, OidcMockTestData.CP_ISSUER_ID
						)},
		};
	}

	private void mockServiceResults(OpenIdProviderConfiguration configuration, ClaimsParty cp) {
		doReturn(OidcMockTestData.REDIRECT_URI).when(apiSupport).getOidcResponseApi(OidcMockTestData.REALM);
		doReturn(configuration).when(oidcMetadataCacheService).getOidcConfiguration(cp);
	}

}
