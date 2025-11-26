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

package swiss.trustbroker.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.config.TrustBrokerProperties;

@AllArgsConstructor(staticName = "of")
@Slf4j
public class HeaderBuilder {

	public static final String STRICT_TRANSPORT_SECURITY = "Strict-Transport-Security";

	public  static final String REFERRER_POLICY = "Referrer-Policy";

	public  static final String ROBOTS_TAG = "X-Robots-Tag";

	public  static final String FRAME_OPTIONS = "X-Frame-Options";

	public  static final String CONTENT_SECURITY_POLICY = "Content-Security-Policy";

	public  static final String CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";

	private final HttpServletRequest request;

	private final HttpServletResponse response;

	private final TrustBrokerProperties properties;

	private final FrameAncestorHandler frameAncestorHandler;

	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
	public HeaderBuilder hsts() {
		if (properties.isSecureBrowserHeaders()) {
			setHeader(STRICT_TRANSPORT_SECURITY, "max-age=6307200");
		}
		return this;
	}

	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
	public HeaderBuilder contentTypeOptions() {
		setHeader(CONTENT_TYPE_OPTIONS, "nosniff");
		return this;
	}

	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
	public HeaderBuilder referrerPolicy() {
		setHeader(REFERRER_POLICY, "origin-when-cross-origin");
		return this;
	}

	// Robot indexing settings. robots.txt controls crawling, while robots header/meta tag control indexing
	// (i.e. also work for external links).
	// Note that header/meta only work if the robot crawls the page, i.e. not for resources disallowed in robots.txt.
	// So robots that support the header/meta tags need to be whitelisted in robots.txt.
	// Header/meta: Google supports 'none' as alias for 'noindex, nofollow', but Bing does not.
	// index.html has 'robots' meta tag for search engines that just support that.
	// robots.txt has 'Disallow /' for non Google/Bing engines to use the header.
	// https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag
	// https://developers.google.com/search/docs/crawling-indexing/robots/create-robots-txt
	// https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0
	// https://www.bing.com/webmasters/help/which-robots-metatags-does-bing-support-5198d240
	public HeaderBuilder robotsTag() {
		if (!request.getRequestURI().equals("/robots.txt")) {
			setHeader(ROBOTS_TAG, "noindex, nofollow");
		}
		return this;
	}

	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
	public HeaderBuilder defaultFrameOptions() {
		return frameOptions(properties.getFrameOptions().getFallback());
	}

	private HeaderBuilder frameOptions(String frameOptions) {
		if (StringUtils.isNotEmpty(frameOptions)) {
			setHeader(FRAME_OPTIONS, frameOptions); // prevent embedding
		}
		return this;
	}

	public HeaderBuilder oidcCspFrameOptions(Set<String> ownOrigins) {
		var frameOptions = properties.getFrameOptions().getOidc();
		var csp = properties.getCsp().getOidc();
		return cspFrameOptions(csp, frameOptions, ownOrigins);
	}

	private HeaderBuilder cspFrameOptions(String csp, String frameOptions, Set<String> ownOrigins) {
		var frameAncestorList = frameAncestorHandler.supportedFrameAncestors();
		Set<String> frameAncestors = new HashSet<>(frameAncestorList);
		if (!CollectionUtils.isEmpty(ownOrigins)) {
			frameAncestors.addAll(ownOrigins);
		}
		var appliedFrameAncestors = new ArrayList<String>();
		csp(csp, frameAncestors, appliedFrameAncestors);
		frameAncestorHandler.appliedFrameAncestors(appliedFrameAncestors);
		frameOptions(appliedFrameAncestors, frameOptions);
		return this;
	}

	public HeaderBuilder oidc3pCookieOptions(String origin, String perimeterUrl) {
		Set<String> ancestors = origin != null ? Set.of(origin) : Set.of();
		var csp = appendFrameAncestors(null, ancestors, null);
		csp = csp + " " + perimeterUrl;
		setHeader(CONTENT_SECURITY_POLICY, csp);
		return this;
	}

	private HeaderBuilder frameOptions(List<String> frameAncestors, String frameOptions) {
		// skip if we have frame ancestors, it does not make sense to have both in any constellation
		if (!CollectionUtils.isEmpty(frameAncestors)) {
			log.debug("Skipping header {}={} as we have frameAncestors={}", FRAME_OPTIONS, frameOptions, frameAncestors);
			return this;
		}
		return frameOptions(frameOptions);
	}

	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
	// Support is removed in newer browsers -> use Content-Security-Policy instead
	// response.setHeader("X-XSS-Protection", "1; mode=block")

	// https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
	public HeaderBuilder defaultCsp() {
		return csp(properties.getCsp().getFallback(), Collections.emptySet(), null);
	}

	private HeaderBuilder csp(String csp, Set<String> allowedFrameAncestors, List<String> appliedFrameAncestors) {
		if (StringUtils.isNotEmpty(csp) || !allowedFrameAncestors.isEmpty()) {
			csp = appendFrameAncestors(csp, allowedFrameAncestors, appliedFrameAncestors);
			setHeader(CONTENT_SECURITY_POLICY, csp);
		}
		return this;
	}

	private String appendFrameAncestors(String csp, Set<String> allowedFrameAncestors, List<String> appliedFrameAncestors) {
		if (allowedFrameAncestors.isEmpty()) {
			return csp;
		}
		// origin determines the frame ancestor to be selected
		var selectedFrameAncestor = CorsSupport.getAllowedOrigin(request, allowedFrameAncestors);
		if (selectedFrameAncestor == null) {
			return csp;
		}
		if (StringUtils.isEmpty(csp)) {
			csp = "";
		}
		else {
			csp += "; ";
		}
		if (appliedFrameAncestors != null) {
			appliedFrameAncestors.add(selectedFrameAncestor);
		}
		return csp + "frame-ancestors 'self' " + selectedFrameAncestor;
	}

	//'unsafe-hashes' (for 'document.forms[0].submit();' in SAML POST binding
	public HeaderBuilder samlCsp() {
		return csp(properties.getCsp().getSaml(), Collections.emptySet(), null);
	}

	public HeaderBuilder frontendCsp() {
		return csp(properties.getCsp().getFrontend(), Collections.emptySet(), null);
	}

	private void setHeader(String name, String value) {
		log.trace("Setting header '{}'='{}'", name, value); // op tracing provides it too
		response.setHeader(name, value);
	}

}
