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
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class SloResponseTest {

	@ParameterizedTest
	@MethodSource
	void isSamlResponseForMode(SloMode mode) {
		var sloUrl = SloResponse.builder().build();
		sloUrl.setMode(mode);
		assertThat(sloUrl.isResponse(SloProtocol.SAML2), is(mode.isResponse()));
	}

	static SloMode[] isSamlResponseForMode() {
		return SloMode.values();
	}

	@ParameterizedTest
	@MethodSource
	void isSamlResponseForProtocol(SloProtocol protocol) {
		var sloUrl = SloResponse.builder().build();
		sloUrl.setProtocol(protocol);
		assertThat(sloUrl.isResponse(SloProtocol.SAML2), is(protocol == SloProtocol.SAML2));
	}

	static SloProtocol[] isSamlResponseForProtocol() {
		return SloProtocol.values();
	}

	@Test
	void hasSloUrlAndIssuerForSamlResponse() {
		var sloUrl = buildWithUrl();
		assertThat(sloUrl.hasSloUrlForResponse(SloProtocol.SAML2), is(true));
		assertThat(sloUrl.hasIssuerForResponse(SloProtocol.SAML2), is(true));
	}

	@Test
	void hasNoSloUrlOrIssuer() {
		var sloUrl = SloResponse.builder().build();
		assertThat(sloUrl.isResponse(SloProtocol.SAML2), is(true)); // default
		assertThat(sloUrl.hasSloUrlForResponse(SloProtocol.SAML2), is(false));
		assertThat(sloUrl.hasIssuerForResponse(SloProtocol.SAML2), is(false));
	}

	@Test
	void hasNoSloUrlOrIssuerForNonSamlResponse() {
		var sloUrl = buildWithUrl();
		sloUrl.setMode(SloMode.NOTIFY_FAIL);
		assertThat(sloUrl.isResponse(SloProtocol.SAML2), is(false));
		assertThat(sloUrl.hasSloUrlForResponse(SloProtocol.SAML2), is(false));
		assertThat(sloUrl.hasIssuerForResponse(SloProtocol.SAML2), is(false));
	}

	@Test
	void hasNoSloUrl() {
		var sloUrl = buildWithUrl();
		sloUrl.setUrl("");
		assertThat(sloUrl.isResponse(SloProtocol.SAML2), is(true));
		assertThat(sloUrl.hasSloUrlForResponse(SloProtocol.SAML2), is(false));
		assertThat(sloUrl.hasIssuerForResponse(SloProtocol.SAML2), is(true));

	}

	@Test
	void hasNoIssuer() {
		var sloUrl = buildWithUrl();
		sloUrl.setIssuer("");
		assertThat(sloUrl.isResponse(SloProtocol.SAML2), is(true));
		assertThat(sloUrl.hasSloUrlForResponse(SloProtocol.SAML2), is(true));
		assertThat(sloUrl.hasIssuerForResponse(SloProtocol.SAML2), is(false));
	}

	@Test
	void isSameExceptMode() {
		var sloUrl1 = buildWithUrl();
		var sloUrl2 = buildWithUrl();
		var sloUrl3 = buildWithUrl();
		sloUrl2.setMode(SloMode.NOTIFY_FAIL);
		sloUrl3.setUrl("any");
		assertThat(sloUrl1.isSameExceptMode(sloUrl2), is(true));
		assertThat(sloUrl2.isSameExceptMode(sloUrl3), is(false));
		assertThat(sloUrl1.isSameExceptMode(sloUrl3), is(false));
	}

	private SloResponse buildWithUrl() {
		return SloResponse.builder()
				.url("https://localhost/slo")
				.issuer("iss1")
				.mode(SloMode.RESPONSE)
				.protocol(SloProtocol.SAML2)
				.build();
	}

	@Test
	void isOidcSessionRequired() {
		var sloUrl = SloResponse.builder().protocol(SloProtocol.OIDC).sessionRequired(true).build();
		assertThat(sloUrl.isOidcSessionRequired(), is(true));
	}

	@Test
	void isOidcSessionNotRequired() {
		var sloUrl = SloResponse.builder().protocol(SloProtocol.OIDC).build();
		assertThat(sloUrl.isOidcSessionRequired(), is(false));
		sloUrl.setSessionRequired(null);
		assertThat(sloUrl.isOidcSessionRequired(), is(false));
	}

	@Test
	void isOidcSessionNotRequiredForOtherProtocol() {
		var sloUrl = SloResponse.builder().protocol(SloProtocol.SAML2).build();
		assertThat(sloUrl.isOidcSessionRequired(), is(false));
	}

	@ParameterizedTest
	@MethodSource
	void isNotification(SloMode mode, SloProtocol protocol, boolean crossProtocol, SloProtocol checkProtocol,
			boolean expected) {
		var sloUrl = SloResponse.builder().mode(mode).protocol(protocol).crossProtocol(crossProtocol).build();
		assertThat(sloUrl.isNotification(checkProtocol), is(expected));
	}

	static Object[][] isNotification() {
		return new Object[][] {
				{ SloMode.NOTIFY_TRY, SloProtocol.SAML2, false, SloProtocol.SAML2, true },
				{ SloMode.RESPONSE_NOTIFY_TRY, SloProtocol.SAML2, false, SloProtocol.SAML2, true },
				{ SloMode.RESPONSE_NOTIFY_FAIL, SloProtocol.SAML2, false, SloProtocol.SAML2, true },
				{ SloMode.RESPONSE, SloProtocol.SAML2, false, SloProtocol.SAML2, false }, // RESPONSE
				{ SloMode.NOTIFY_FAIL, SloProtocol.SAML2, false, SloProtocol.OIDC, false }, // not crossProtocol
				{ SloMode.NOTIFY_FAIL, SloProtocol.SAML2, true, SloProtocol.OIDC, true }, // crossProtocol
				{ SloMode.NOTIFY_FAIL, SloProtocol.HTTP, false, SloProtocol.OIDC, true } // HTTP is crossProtocol
		};
	}

	@ParameterizedTest
	@MethodSource
	void isResponse(SloMode mode, SloProtocol protocol, SloProtocol checkProtocol, boolean expected) {
		var sloUrl = SloResponse.builder().mode(mode).protocol(protocol).build();
		assertThat(sloUrl.isResponse(checkProtocol), is(expected));
	}

	static Object[][] isResponse() {
		return new Object[][] {
				{ SloMode.RESPONSE, SloProtocol.SAML2, SloProtocol.SAML2, true },
				{ SloMode.RESPONSE_NOTIFY_FAIL, SloProtocol.SAML2, SloProtocol.SAML2, true },
				{ SloMode.RESPONSE_NOTIFY_TRY, SloProtocol.SAML2, SloProtocol.SAML2, true },
				{ SloMode.NOTIFY_FAIL, SloProtocol.SAML2, SloProtocol.SAML2, false }, // NOTIFY
				{ SloMode.RESPONSE, SloProtocol.SAML2, SloProtocol.OIDC, false } // cross protocol
		};
	}

}
