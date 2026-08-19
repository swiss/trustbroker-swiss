/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

package swiss.trustbroker.homerealmdiscovery.service;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.codec.HTMLEncoder;
import org.apache.velocity.app.VelocityEngine;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.saml.util.VelocityUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.util.WebSupport;

/**
 * Output redirect in a form suitable for a calling script (XMLHttpRequest/fetch).
 */
@Service
@AllArgsConstructor
@Slf4j
public class RedirectOutputService {

	private final VelocityEngine velocityEngine;

	private final TrustBrokerProperties trustBrokerProperties;

	/**
	 * Absolute redirects are rendered via a page that auto-forwards to the link as they may be 3rd party / CORS without access
	 * granted to the calling script.
	 * <br/>
	 * Note: Caller must generate/validate redirectUrl to avoid open redirects.
	 * @return URL to redirect to or null if there's no redirect or the redirect was handled by this method .
	 */
	public String handleRedirect(HttpServletRequest request, HttpServletResponse response, String redirectUrl) {
		if (redirectUrl == null) {
			return null;
		}
		var uri = WebUtil.getValidatedUri(redirectUrl);
		if (uri == null) {
			log.warn("Not redirecting to invalid redirectUrl={}", redirectUrl);
			return null;
		}
		if (!uri.isAbsolute()) {
			log.debug("Redirecting to relative redirectUrl={}", redirectUrl);
			return redirectUrl;
		}
		if (!WebUtil.isCorsRequest(request)) {
			log.debug("Not CORS - redirecting to redirectUrl={}", redirectUrl);
			return redirectUrl;
		}
		if (WebSupport.isOwnOrigin(trustBrokerProperties, uri)) {
			log.debug("Redirecting to same origin redirectUrl={}", redirectUrl);
			return redirectUrl;
		}
		log.info("Redirecting to cross origin redirectUrl={} via HTML template", redirectUrl);
		var split = WebUtil.splitQueryParameters(redirectUrl, true);
		Map<String, Object> velocityParams = new HashMap<>();
		velocityParams.put(VelocityUtil.VELOCITY_PARAM_XTB_HTTP_METHOD, HttpMethod.GET.name());
		velocityParams.put(VelocityUtil.VELOCITY_PARAM_ACTION, HTMLEncoder.encodeForHTMLAttribute(split.getKey()));
		// attribute keys and values are HTML encoded already:
		velocityParams.put(VelocityUtil.VELOCITY_PARAM_ADDITIONAL_FIELDS, split.getValue());
		VelocityUtil.renderTemplate(velocityEngine, response, VelocityUtil.VELOCITY_REDIRECT_TEMPLATE_ID, velocityParams);
		return null;
	}
}
