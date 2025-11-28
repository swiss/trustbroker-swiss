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

package swiss.trustbroker.gui;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;

@TestConfiguration
class GuiSupportTest {

	private static final String NAME = "THEME";

	private static final String VALUE = "test";

	private static final String DOMAIN = "test.example.trustbroker.swiss";

	private static final String PATH = "/path";

	@Test
	void getTheme() {
		var request = new MockHttpServletRequest();
		assertThat(GuiSupport.getTheme(request, null), is(nullValue()));
		request.setCookies(new Cookie(NAME, VALUE));
		var config = givenConfig();
		assertThat(GuiSupport.getTheme(request, config.getGui()), is(VALUE));
	}

	@Test
	void addThemeIndicator() {
		var response = new MockHttpServletResponse();
		var config = givenConfig();
		assertDoesNotThrow(() -> GuiSupport.addThemeIndicator(response, config));
		var cookie = response.getCookie(NAME);
		assertThat(cookie, is(not(nullValue())));
		assertThat(cookie.getValue(), is(VALUE));
		assertThat(cookie.getDomain(), is(DOMAIN));
		assertThat(cookie.getPath(), is(PATH));
		assertThat(cookie.getAttribute(WebUtil.COOKIE_SAME_SITE), is(WebUtil.COOKIE_SAME_SITE_STRICT));
	}

	@Test
	void addThemeIndicatorSameSiteFallback() {
		var response = new MockHttpServletResponse();
		var config = givenConfig();
		config.setCookieSameSite(WebUtil.COOKIE_SAME_SITE_LAX);
		config.getGui().getThemeCookie().setSameSite(null);
		assertDoesNotThrow(() -> GuiSupport.addThemeIndicator(response, config));
		var cookie = response.getCookie(NAME);
		assertThat(cookie.getAttribute(WebUtil.COOKIE_SAME_SITE), is(WebUtil.COOKIE_SAME_SITE_LAX));
	}

	@Test
	void addThemeIndicatorIgnoreSameSiteDynamic() {
		var response = new MockHttpServletResponse();
		var config = givenConfig();
		config.getGui().getThemeCookie().setSameSite(WebUtil.COOKIE_SAME_SITE_DYNAMIC);
		assertDoesNotThrow(() -> GuiSupport.addThemeIndicator(response, config));
		var cookie = response.getCookie(NAME);
		assertThat(cookie.getAttribute(WebUtil.COOKIE_SAME_SITE), is(nullValue()));
	}

	@Test
	void addSkipAddingThemeIndicator() {
		var response = new MockHttpServletResponse();
		var trustBrokerProperties = new TrustBrokerProperties();
		assertDoesNotThrow(() -> GuiSupport.addThemeIndicator(response, trustBrokerProperties));
		trustBrokerProperties.getGui().getThemeCookie().setName("");
		assertDoesNotThrow(() -> GuiSupport.addThemeIndicator(response, trustBrokerProperties));
		assertThat(response.getCookie(""), is(nullValue()));
		trustBrokerProperties.getGui().getThemeCookie().setName(NAME);
		assertDoesNotThrow(() -> GuiSupport.addThemeIndicator(response, trustBrokerProperties));
		assertThat(response.getCookie(NAME), is(nullValue()));
		trustBrokerProperties.getGui().getThemeCookie().setDefaultValue("");
		assertDoesNotThrow(() -> GuiSupport.addThemeIndicator(response, trustBrokerProperties));
		assertThat(response.getCookie(NAME), is(nullValue()));
	}

	@Test
	void addThemeIndicatorIfMissing() {
		var request = new MockHttpServletRequest();
		var response = new MockHttpServletResponse();
		var trustBrokerProperties = new TrustBrokerProperties();
		assertDoesNotThrow(() -> GuiSupport.addThemeIndicatorIfMissing(request, response, trustBrokerProperties));
		var config = givenConfig();
		assertDoesNotThrow(() -> GuiSupport.addThemeIndicatorIfMissing(request, response, config));
		var cookie = response.getCookie(NAME);
		assertThat(cookie, is(not(nullValue())));
		assertThat(cookie.getValue(), is(VALUE));
		assertThat(cookie.getDomain(), is(DOMAIN));
		assertThat(cookie.isHttpOnly(), is(false));
		assertThat(cookie.getSecure(), is(true));
		assertThat(cookie.getPath(), is(PATH));
		assertThat(cookie.getMaxAge(), is(-1));
	}

	@Test
	void addThemeIndicatorIfNotMissing() {
		var request = new MockHttpServletRequest();
		var response = new MockHttpServletResponse();
		var config = givenConfig();
		var cookieValue = "custom";
		request.setCookies(new Cookie(NAME, cookieValue));
		assertDoesNotThrow(() -> GuiSupport.addThemeIndicatorIfMissing(request, response, config));
		var cookie = response.getCookie(NAME);
		assertThat(cookie, is(nullValue()));
	}

	private static TrustBrokerProperties givenConfig() {
		var properties = new TrustBrokerProperties();
		var config = properties.getGui();
		config.getThemeCookie().setName(NAME);
		config.getThemeCookie().setDefaultValue(VALUE);
		config.getThemeCookie().setDomain("." + DOMAIN); // simulate leading dot
		config.getThemeCookie().setPath(PATH);
		config.getThemeCookie().setSameSite(WebUtil.COOKIE_SAME_SITE_STRICT);
		properties.setGui(config);
		return properties;
	}

}
