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

package swiss.trustbroker.federation.xmlconfig;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class RelyingPartyTest {

	private static final String SLO_ATTR_URL = "https://localhost/slo/attribute";

	private static final String SLO_ELEMENT_URL = "https://localhost/slo/element";

	private static final String SLO_ISSUER = "issuer1";

	@Test
	void getSloUrlIssuerWithoutSloResponse() {
		// missing SLO config
		var rp = RelyingParty.builder().build();
		assertThat(rp.getSloUrl(SloProtocol.SAML2), is(Optional.empty()));
		assertThat(rp.getSloIssuer(SloProtocol.SAML2), is(Optional.empty()));
		var sso = Sso.builder().sloUrl("").build();
		rp.setSso(sso);
		assertThat(rp.getSloUrl(SloProtocol.SAML2), is(Optional.empty()));
		assertThat(rp.getSloIssuer(SloProtocol.SAML2), is(Optional.empty()));
	}

	@Test
	void getSloUrlIssuerWithoutSloUrlElement() {
		var rp = buildRp("", "");
		assertThat(rp.getSloUrl(SloProtocol.SAML2), is(Optional.empty()));
		assertThat(rp.getSloIssuer(SloProtocol.SAML2), is(Optional.empty()));
	}

	@Test
	void getSloUrlIssuerFromSloUrlElement() {
		var rp = buildRp(SLO_ELEMENT_URL, SLO_ISSUER);
		assertThat(rp.getSloUrl(SloProtocol.SAML2), is(Optional.of(SLO_ELEMENT_URL)));
		assertThat(rp.getSloIssuer(SloProtocol.SAML2), is(Optional.of(SLO_ISSUER)));
	}

	@Test
	void getSloUrlAttributeOverridesSloUrl() {
		var rp = buildRp(SLO_ELEMENT_URL, null);
		rp.getSso().setSloUrl(SLO_ATTR_URL);
		assertThat(rp.getSloUrl(SloProtocol.SAML2), is(Optional.of(SLO_ATTR_URL)));
	}

	@Test
	void getSloUrlOnlyUsedForSaml() {
		var rp = buildRp(null, null);
		rp.getSso().setSloUrl(SLO_ATTR_URL);
		assertThat(rp.getSloUrl(SloProtocol.SAML2), is(Optional.of(SLO_ATTR_URL)));
		assertThat(rp.getSloUrl(SloProtocol.OIDC), is(Optional.empty()));
		assertThat(rp.getSloUrl(SloProtocol.HTTP), is(Optional.empty()));
	}

	private RelyingParty buildRp(String url, String issuer) {
		var sso = Sso.builder().sloUrl("").build();
		var rp = RelyingParty.builder().sso(sso).build();
		var sloResponse = SloResponse.builder().build(); // without URL -> skipped
		sso.getSloResponse().add(sloResponse);
		sloResponse = SloResponse.builder().url(url).issuer(issuer).build();
		sso.getSloResponse().add(sloResponse);
		if (StringUtils.isNotEmpty(url)) {
			sloResponse = SloResponse.builder().url("https://localhost").build(); // second match ignored
			sso.getSloResponse().add(sloResponse);
		}
		if (StringUtils.isNotEmpty(issuer)) {
			sloResponse = SloResponse.builder().issuer("otherIssuer").build(); // second match ignored
			sso.getSloResponse().add(sloResponse);
		}
		return rp;
	}

	@Test
	void requireSignedRequest() {
		var rp = RelyingParty.builder().build();
		assertThat(rp.requireSignedAuthnRequest(), is(true));
		assertThat(rp.requireSignedLogoutRequest(), is(true));
		var secPol = SecurityPolicies.builder().build();
		rp.setSecurityPolicies(secPol);
		assertThat(rp.requireSignedAuthnRequest(), is(true));
		assertThat(rp.requireSignedLogoutRequest(), is(true));
		secPol.setRequireSignedAuthnRequest(null);
		assertThat(rp.requireSignedAuthnRequest(), is(true));
		secPol.setRequireSignedLogoutRequest(null);
		assertThat(rp.requireSignedLogoutRequest(), is(true));
	}

	@Test
	void doNotRequireSignedAuthnRequest() {
		var secPol = SecurityPolicies.builder().requireSignedAuthnRequest(false).build();
		var rp = RelyingParty.builder().securityPolicies(secPol).build();
		assertThat(rp.requireSignedLogoutRequest(), is(true));
		assertThat(rp.requireSignedAuthnRequest(), is(false));
		assertThat(rp.requireSignedLogoutRequest(), is(true));
	}

	@Test
	void doNotRequireSignedLogoutRequest() {
		var secPol = SecurityPolicies.builder().requireSignedLogoutRequest(false).build();
		var rp = RelyingParty.builder().securityPolicies(secPol).build();
		assertThat(rp.requireSignedLogoutRequest(), is(false));
		assertThat(rp.requireSignedAuthnRequest(), is(true));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"false,true,false",
			"true,false,true",
			"null,false,false",
			"null,true,true"
	}, nullValues = "null")
	void doNotRequireSignedResponse(Boolean requireSignedResponse, boolean defaultValue, boolean result) {
		var secPol = SecurityPolicies.builder().requireSignedResponse(requireSignedResponse).build();
		var rp = RelyingParty.builder().securityPolicies(secPol).build();
		assertThat(rp.requireSignedResponse(defaultValue), is(result));
	}

	@Test
	void getOidcClientsNoneDefined() {
		var rpWithoutOidc = RelyingParty.builder().build(); // no OIDC
		assertThat(rpWithoutOidc.getOidcClients(), is(Collections.emptyList()));
	}

	@Test
	void getOidcClients() {
		var client1 = OidcClient.builder().id("clientId1").build();
		var client2 = OidcClient.builder().id("clientId2").build();
		var oidcClients = List.of(client1, client2);
		var rpWithOidc = RelyingParty.builder()
				.oidc(Oidc.builder().clients(oidcClients).build())
				.build();
		assertThat(rpWithOidc.getOidcClients(), is(oidcClients));
	}

	@Test
	void isDelegateOrigin() {
		var rp = RelyingParty.builder().build();
		assertThat(rp.isDelegateOrigin(), is(true));
		var secPol = SecurityPolicies.builder().build();
		rp.setSecurityPolicies(secPol);
		assertThat(rp.isDelegateOrigin(), is(true));
		secPol.setDelegateOrigin(false);
		assertThat(rp.isDelegateOrigin(), is(false));
	}

	@Test
	void getCpMappingForAliasNoMappings() {
		var rp = RelyingParty.builder().build();
		// no mappings
		assertThat(rp.getCpMappingForAlias("alias"), is(Optional.empty()));
	}

	@Test
	void getCpMappingForAliasNoProviderList() {
		var rp = RelyingParty.builder().claimsProviderMappings(ClaimsProviderMappings.builder().build()).build();
		assertThat(rp.getCpMappingForAlias("alias"), is(Optional.empty()));
	}

	@Test
	void getCpMappingForAlias() {
		var alias = "rpAlias1";
		var cpId = "cp3";
		var cpList = List.of(
				ClaimsProvider.builder().id("cp1").build(),
				ClaimsProvider.builder().id("cp2").relyingPartyAlias("rp2").build(),
				ClaimsProvider.builder().id(cpId).relyingPartyAlias(alias).build()
		);
		var rp =
				RelyingParty.builder().claimsProviderMappings(
						ClaimsProviderMappings.builder().claimsProviderList(cpList).build()
				).build();

		// wrong alias
		assertThat(rp.getCpMappingForAlias(null), is(Optional.empty()));
		assertThat(rp.getCpMappingForAlias("rpAlias2"), is(Optional.empty()));
		// matching alias
		assertThat(rp.getCpMappingForAlias(alias), is(not(Optional.empty())));
		assertThat(rp.getCpMappingForAlias(alias).get().getId(), is(cpId));
	}

}
