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

package swiss.trustbroker.oidc.sso.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.dto.CookieParameters;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;

@SpringBootTest(classes = OidcSessionController.class)
class OidcSessionControllerTest {

	@MockitoBean
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@Autowired
	private OidcSessionController oidcSessionController;

	private MockHttpServletRequest request;


	@BeforeEach
	void setUp() {
		request = new MockHttpServletRequest();
	}

	@Test
	void getCookieByNameTest() {
		String cookieName = "SESSION_COOKIE";

		request.setCookies(givenCookie(cookieName));
		Cookie cookie = oidcSessionController.getCookieByName(request, cookieName);
		assertNotNull(cookie);
		assertEquals(cookie.getName(), cookieName);

		request.setCookies(givenCookie("any"));
		Cookie cookie2 = oidcSessionController.getCookieByName(request, cookieName);
		assertNull(cookie2);
	}

	private Cookie givenCookie(String cookieName) {
		var params = CookieParameters.builder()
									 .name(cookieName)
									 .value(cookieName)
									 .maxAge(20)
									 .build();
		return WebUtil.createCookie(params);
	}


}
