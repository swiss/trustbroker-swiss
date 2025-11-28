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

package swiss.trustbroker.common.util;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.common.exception.TechnicalException;

class OidcUtilTest {

	@ParameterizedTest
	@CsvSource({
			",,,",
			",iss1,,", // iss alone not allowed
			",,sess1,", // sid alone not allowed
			",iss1,sess1,?iss=iss1&sid=sess1",
			"https//localhost,iss1,sess1,https//localhost?iss=iss1&sid=sess1",
			",https://issuer,https://session,?iss=https%3A%2F%2Fissuer&sid=https%3A%2F%2Fsession",
	})
	void appendFrontchannelLogoutQueryString(String url, String iss, String sid, String result) {
		assertThat(OidcUtil.appendFrontchannelLogoutQueryString(url, iss, sid), is(result));
	}

	@ParameterizedTest
	@CsvSource({
			"https://host1/path,false",
			"https://host1/path/subpath,true",
			"https://host1/path/subpath/,false",
			"https://host2/path/any,true",
			"https://host2/path/any/subpath,true",
			"https://host3,true",
			"https://host3/,true",
			"https://host3/any,true",
			"https://host3:443/any,true",
			"https://host3/any/subpath,true",
			"https://host4/any,true",
			"https://host4:443/any,true"
	})
	void testRedirectUriMatch(String url, boolean expectedResult) {
		var config = Set.of(
				"https://host1/path/subpath",
				"https://host2/path/.*",
				"https://host3/.*",
				"https://host4:443/.*"
		);
		assertThat(UrlAcceptor.isRedirectUrlOkForAccess(url, config), is(expectedResult));
	}

	@Test
	void testClientIdFromAuthorizationValid() {
		var authHeader = "bearer " +
				"eyJraWQiOiIyM2Q2ZTNhZC1iZDc3LTRmZDAtYWE2ZC0wMWE3NGI1NjFmMjciLCJhbGciOiJSUzI1NiJ9." +
				"eyJzdWIiOiIxMjM0NSIsImF1ZCI6IlRFU1RSUCIsImFjciI6WyJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpOb21hZFRlbGVwaG9ueSJdLCJuYmYiOjE2ODkwOTEyNTEsInNjb3BlIjpbIm9wZW5pZCIsImVtYWlsIl0sImF1dGhfdGltZSI6MTY4OTA5MTI1MSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiZXhwIjoxNjg5MDkyNDUxLCJpYXQiOjE2ODkwOTEyNTEsImp0aSI6IjYyNmZiNzgzLWQ3MDYtNGI0Yy05NDk0LThkMjI4OTI2NWIyYiJ9Cg." +
				"makYE597FiXOAjRPBifze-6PHJxR6XQmVBmqTf5IifNGyMAuUJnei0nJbmFPuAYQeBgkXbZk8zqcl8jggiAVvdgS-tkY_VRBeibCcAyO_JePfgLWK0GsTBpoK4PuQoWn9OY2w43WYIpG--XsiVRnPuBXJVTkR4zc2X_Z7xpAUoFdUJd-4eLc1Mr1L4JPRDSOFGzHE_Hd4e3DxXQ6ilkKFxzFLgoHz8ohWt4m8x9iur7EQ-AY3H-yaQkT8zoAR67hcYrkuiCV2KArKyIPmMdThi-evbbTd-opcDDlc2GhjsR9XKsv-nI8S7tmjx99ljTiN93nvuVnil_iUoNqdSG8MA";
		var clId = OidcUtil.getClientIdFromAuthorizationHeader(authHeader);
		assertThat(clId, equalTo("TESTRP"));
	}

	@Test
	void testClientIdFromBasicAuth() {
		var authHeader = "Basic Y2xpZW50SUQ6c2VjcmV0Cg==";
		var clId = OidcUtil.getClientIdFromAuthorizationHeader(authHeader);
		assertThat(clId, equalTo("clientID"));
	}

	@Test
	void testClientIdFromAuthorizationInvalid() {
		// ERROR log only
		var clId = OidcUtil.getClientIdFromAuthorizationHeader("invalid");
		assertThat(clId, nullValue());
	}

	@ParameterizedTest
	@CsvSource(value = {
			"https://trustbroker.swiss,secret:1,Basic aHR0cHMlM0ElMkYlMkZ0cnVzdGJyb2tlci5zd2lzczpzZWNyZXQlM0Ex",
			"client,1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890,Basic Y2xpZW50OjEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA="
	})
	void testGetBasicAuthorizationHeader(String clientId, String secret, String expected) {
		assertThat(OidcUtil.getBasicAuthorizationHeader(clientId, secret), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"token,Bearer token",
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890,Bearer 1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
	})
	void testGetBearerAuthorizationHeader(String token, String expected) {
		assertThat(OidcUtil.getBearerAuthorizationHeader(token), is(expected));
	}

	@Test
	void testParseJwtClaimsEmpty() {
		var emptyResult = new JWTClaimsSet.Builder().build();
		assertThat(OidcUtil.parseJwtClaims(null), is(emptyResult));
		assertThat(OidcUtil.parseJwtClaims(""), is(emptyResult));
	}

	@Test
	void testParseJwtClaimsInvalid() {
		assertThrows(TechnicalException.class, () -> OidcUtil.parseJwtClaims("{"));
	}

	@Test
	void testParseJwtClaims() {
		var result = OidcUtil.parseJwtClaims("""
				{ "sub": "subject", "numbers": [ 1, 2, 3 ]}
				""");
		assertThat(result.getSubject(), is("subject"));
		assertThat(result.getClaim("numbers"), instanceOf(List.class));
	}

	@Test
	void testMergeJwtClaims() throws Exception {
		var primary = JWTClaimsSet.parse(Map.of(
				OidcUtil.OIDC_SUBJECT, "sub1",
				OidcUtil.OIDC_SESSION_ID, "session1",
				OidcUtil.OIDC_AUTHORIZED_PARTY, "party1"
		));
		assertThat(OidcUtil.mergeJwtClaims(primary, "primary", null, null), is(primary));
		var secondary = JWTClaimsSet.parse(Map.of(
				OidcUtil.OIDC_SUBJECT, "sub1",
				OidcUtil.OIDC_ACR, "acr1",
				OidcUtil.OIDC_AUTHORIZED_PARTY, "party2"
		));
		assertThat(OidcUtil.mergeJwtClaims(null, "primary", secondary, null), is(secondary));
		var result = OidcUtil.mergeJwtClaims(primary, "primary", secondary, "secondary");
		// same
		assertThat(result.getSubject(), is("sub1"));
		// primary wins
		assertThat(result.getClaim(OidcUtil.OIDC_AUTHORIZED_PARTY), is("party1"));
		// primary or secondary only
		assertThat(result.getClaim(OidcUtil.OIDC_ACR), is("acr1"));
		assertThat(result.getClaim(OidcUtil.OIDC_SESSION_ID), is("session1"));
	}

	@Test
	void testGenerateNonce() {
		var nonce = OidcUtil.generateNonce();
		assertThat(nonce.length(), is(32));
		assertThat(nonce, not(containsString("-")));
	}

	@ParameterizedTest
	@MethodSource
	void testConvertAcrToContextClasses(String acr, List<String> expectedClasses) {
		assertThat(OidcUtil.convertAcrToContextClasses(acr), is(expectedClasses));
	}

	public static Object[][] testConvertAcrToContextClasses() {
		return new Object[][] {
				{ null, Collections.emptyList() },
				{ "", Collections.emptyList() },
				{ "qoa:10", List.of("qoa:10") },
				{ "qoa:10 qoa:20 qoa:30", List.of("qoa:10", "qoa:20", "qoa:30") }
		};
	}

}
