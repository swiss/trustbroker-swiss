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

package swiss.trustbroker.config;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.apache.tomcat.util.http.SameSiteCookies;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;

class TrustbrokerCookieProcessorTest {

	@ParameterizedTest
	@CsvSource(value = {
		"false,null,Unset,null,https://localhost",
		"false,None,Unset,null", // None without secure
		"false,Strict,Strict,null",
		"true,None,None,null",
		"true,Strict,Strict,null"
	}, nullValues = "null")
	void calculateDefaultSameSite(boolean secure, String sameSite, String expectedSameSite, String perimeterUrl) {
		var properties = new TrustBrokerProperties();
		properties.setSecureBrowserHeaders(secure);
		properties.setCookieSameSite(sameSite);
		properties.setPerimeterUrl(perimeterUrl);
		var processor = new TrustbrokerCookieProcessor(properties);
		assertThat(processor.getDefaultSameSite(), is(expectedSameSite));
		assertThat(processor.getPerimeterUrl(), is(perimeterUrl));
		// default case:
		assertThat(processor.getSameSiteCookies(), is(SameSiteCookies.fromString(expectedSameSite)));
	}

	@ParameterizedTest
	@MethodSource
	void getSameSiteCookies(String redirectUri, String perimeterUrl, String expected) {
		var request = new MockHttpServletRequest();
		request.setSecure(redirectUri != null && redirectUri.startsWith("https"));
		request.setParameter(OidcUtil.REDIRECT_URI, redirectUri);
		var response = new MockHttpServletResponse();
		HttpExchangeSupport.begin(request, response);
		var properties = new TrustBrokerProperties();
		properties.setPerimeterUrl(perimeterUrl);
		var processor = new TrustbrokerCookieProcessor(properties);
		assertThat(processor.getSameSiteCookies(), is(SameSiteCookies.fromString(expected)));
	}

	static Object[][] getSameSiteCookies() {
		return new Object[][] {
				{ null, null, WebUtil.COOKIE_SAME_SITE_NONE },
				{ "https://localhost/app", "https://localhost/login", WebUtil.COOKIE_SAME_SITE_STRICT },
				{ "https://trustbroker.swiss/app", "https://localhost/login", WebUtil.COOKIE_SAME_SITE_NONE },
				{ "https://sub.trustbroker.swiss/app", "https://auth.trustbroker.swiss/login", WebUtil.COOKIE_SAME_SITE_STRICT }
		};
	}
}
