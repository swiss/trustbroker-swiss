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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.common.dto.CookieParameters;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.CookieProperties;
import swiss.trustbroker.config.dto.GuiProperties;
import swiss.trustbroker.homerealmdiscovery.dto.CookieConfig;
import swiss.trustbroker.homerealmdiscovery.dto.GuiConfig;

@Slf4j
public class GuiSupport {

	private GuiSupport() {
	}

	static String getTheme(HttpServletRequest request, GuiProperties config) {
		var themeIndicator = config != null ? config.getThemeCookie().getName() : null;
		if (StringUtils.isEmpty(themeIndicator)) {
			return null;
		}
		return WebUtil.getCookie(themeIndicator, request);
	}

	@SuppressWarnings("java:S3330") // cookie contains only theme and needs to be accessible in Javascript
	static void addThemeIndicator(HttpServletResponse response, TrustBrokerProperties trustBrokerProperties) {
		var config = trustBrokerProperties.getGui().getThemeCookie();
		if (StringUtils.isEmpty(config.getName()) || StringUtils.isEmpty(config.getDefaultValue())) {
			log.debug("Not setting themeCookie, name and defaultValue not defined: {}", config);
			return;
		}
		var cookieParams = CookieParameters.builder()
										   .name(config.getName())
										   .value(config.getDefaultValue())
										   .maxAge(config.getMaxAge())
										   .secure(isCookieSecure(config, trustBrokerProperties))
										   .httpOnly(false) // we need to extract it in the UI
										   .domain(getCookieDomain(config))
										   .path(config.getPath())
										   .sameSite(getCookieSameSite(config, trustBrokerProperties))
										   .build();
		var themeCookie = WebUtil.createCookie(cookieParams);
		log.debug("Setting themeCookie based on: config={} params={}", config, cookieParams);
		response.addCookie(themeCookie);
	}

	public static void addThemeIndicatorIfMissing(HttpServletRequest request, HttpServletResponse response,
			TrustBrokerProperties trustBrokerProperties) {
		var requestTheme = getTheme(request, trustBrokerProperties.getGui());
		if (requestTheme == null) {
			addThemeIndicator(response, trustBrokerProperties);
		}
	}

	private static boolean isCookieSecure(CookieProperties config, TrustBrokerProperties trustBrokerProperties) {
		return config.getSecure() != null ? config.getSecure() : trustBrokerProperties.isSecureBrowserHeaders();
	}

	private static String getCookieSameSite(CookieProperties config, TrustBrokerProperties trustBrokerProperties) {
		var sameSite = config.getSameSite();
		if (sameSite == null) {
			sameSite = trustBrokerProperties.getCookieSameSite();
		}
		if (WebUtil.isSameSiteDynamic(sameSite)) {
			log.warn("Ignoring invalid config sameSite={} not supported for GUI cookie={}", sameSite, config.getName());
			return null;
		}
		return sameSite;
	}

	private static String getCookieDomain(CookieProperties config) {
		var domain = config.getDomain();
		if (domain == null) {
			return null;
		}
		// Tomcat Rfc26265CookieProcessor does not support leading dots - they should be ignored according to the RFC.
		// https://www.rfc-editor.org/rfc/rfc6265#section-4.1.2.3
		// This is different fom the old RFC (IE8/9) where the dot was required:
		// https://www.rfc-editor.org/rfc/rfc2109#section-4.2.2
		return domain.replaceAll("^[.]", "");
	}

	public static GuiConfig buildConfig(GuiProperties config) {
		return GuiConfig.builder()
				.languageCookie(buildConfig(config.getLanguageCookie()))
				.themeCookie(buildConfig(config.getThemeCookie()))
				.announcementCookie(buildConfig(config.getAnnouncementCookie()))
				.buttons(config.getButtons())
				.features(config.getFeatures())
				.build();
	}

	private static CookieConfig buildConfig(CookieProperties properties) {
		return CookieConfig.builder()
				.name(properties.getName())
				.domain(properties.getDomain())
				.path(properties.getPath())
				.maxAge(properties.getMaxAge())
				.values(properties.getValues())
				.defaultValue(properties.getDefaultValue())
				.secure(properties.getSecure())
				.sameSite(properties.getSameSite())
			   .build();
	}
}
