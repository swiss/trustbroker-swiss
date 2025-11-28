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

import lombok.AccessLevel;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.apache.tomcat.util.http.SameSiteCookies;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;
import swiss.trustbroker.oidc.session.OidcSessionSupport;

/**
 * Extension of Tomcat Rfc6265CookieProcessor to implement dynamic sameSite attributes.
 */
@Slf4j
@Getter(value = AccessLevel.PACKAGE) // for test
public class TrustbrokerCookieProcessor extends Rfc6265CookieProcessor {

	private final String perimeterUrl;

	private final String defaultSameSite;

	public TrustbrokerCookieProcessor(TrustBrokerProperties trustBrokerProperties) {
		perimeterUrl = trustBrokerProperties.getPerimeterUrl();
		defaultSameSite = calculateDefaultSameSite(trustBrokerProperties);
		// value in super should not matter as we override the getter
		setSameSiteCookies(defaultSameSite);
	}

	@Override
	public SameSiteCookies getSameSiteCookies() {
		var sameSiteFlag = calculateSameSiteForUrl();
		return SameSiteCookies.fromString(sameSiteFlag);
	}

	private String calculateSameSiteForUrl() {
		var request = HttpExchangeSupport.getRunningHttpRequest();
		if (request == null || !request.isSecure()) {
			log.debug("Request is not secure, use SameSite={}", defaultSameSite);
			return defaultSameSite;
		}
		var redirectUri = OidcSessionSupport.getRedirectUri(request);
		if (redirectUri == null) {
			log.debug("Request cannot be checked against redirect_uri, use SameSite={}", defaultSameSite);
			return defaultSameSite;
		}
		var sameSiteFlag = WebUtil.getCookieSameSite(perimeterUrl, redirectUri);
		log.debug("Cookie sameSite={} for redirectUri={}", sameSiteFlag, redirectUri);
		return sameSiteFlag;
	}

	private static String calculateDefaultSameSite(TrustBrokerProperties trustBrokerProperties) {
		String sameSite = SameSiteCookies.UNSET.getValue();
		// SameSite NONE is not supported without the secure flag:
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
		if (trustBrokerProperties.getCookieSameSite() != null && (trustBrokerProperties.isSecureBrowserHeaders() ||
				!trustBrokerProperties.getCookieSameSite().equals(WebUtil.COOKIE_SAME_SITE_NONE))) {
			sameSite = trustBrokerProperties.getCookieSameSite();
		}
		log.debug("Configured cookie defaultSameSite={}", sameSite);
		return sameSite;
	}
}
