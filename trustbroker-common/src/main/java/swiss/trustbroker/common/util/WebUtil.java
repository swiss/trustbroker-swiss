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

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

import com.google.common.net.InternetDomainName;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.utils.DateUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.common.dto.CookieParameters;
import swiss.trustbroker.common.tracing.OpTraceUtil;

/**
 * Log-able web input (where we do not expected any StringUtil.clean modified data) and other helpers.
 */
@Slf4j
public class WebUtil {

	public static final String HTTP_HEADER_X_FORWARDED_FOR = "X-Forwarded-For"; // set by loadbalancer or other infra in front

	public static final String HTTP_HEADER_X_ORIGINAL_FORWARDED_FOR = "X-Original-Forwarded-For"; // observed, derived from X-F-F

	public static final String HTTP_HEADER_X_SIMULATED_FORWARDED_FOR = "X-Simulated-Forwarded-For"; // simulate device or gateway

	public static final String HTTP_HEADER_X_REAL_IP = "X-Real-Ip"; // direct client

	public static final String HTTP_REMOTE_USER = "X-Remote-User";

	public static final String MEDIA_TYPE_SOAP_12 = "application/soap+xml";


	// Same site values
	// See also:
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value
	// https://developer.mozilla.org/en-US/docs/Glossary/Site
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site

	public static final String COOKIE_SAME_SITE = "SameSite";

	public static final String COOKIE_SAME_SITE_NONE = "None"; // see tomcat SameSiteCookies

	public static final String COOKIE_SAME_SITE_LAX = "Lax";

	public static final String COOKIE_SAME_SITE_STRICT = "Strict";

	public static final String COOKIE_SAME_SITE_DYNAMIC = "Dynamic"; // XTB config value - choose based on involved URLs

	public static final String CACHE_CONTROL_NO_CACHE = "no-cache, no-store, max-age=0, must-revalidate";

	public static final String PRAGMA_NO_CACHE = "no-cache";

	public static final String CACHE_CONTROL_MAX_AGE = "public, max-age=";

	private WebUtil() {
	}

	public static String getHeader(String name, HttpServletRequest request) {
		return StringUtil.clean(request.getHeader(name));
	}

	public static String getParameter(String name, HttpServletRequest request) {
		return StringUtil.clean(request.getParameter(name));
	}

	public static String getCookie(String name, HttpServletRequest request) {
		var cookies = request.getCookies();
		if (cookies != null) {
			var ret = Arrays.stream(cookies).filter(c -> c.getName().equals(name)).findFirst();
			return ret.map(Cookie::getValue).orElse(null);
		}
		return null;
	}

	public static String getUserAgent(HttpServletRequest request) {
		return getHeader(HttpHeaders.USER_AGENT, request);
	}

	public static String getClientIp(HttpServletRequest request) {
		return getClientIp(request, true);
	}

	// Track problems based on IP addresses the user agents have (attacks, debugging login problems)
	public static String getClientIp(HttpServletRequest request, boolean tagged) {
		if (request == null) {
			return OpTraceUtil.HOST_IP_HEX_8;
		}
		var ips = getClientIps(request, tagged);
		if (ips.length > 0) {
			return ips[0]; // first entry is client
		}
		return null;
	}

	// for tests only, for gateway check we have a look at all IPs in the chain
	public static String getGatewayIp(HttpServletRequest request) {
		return getGatewayIp(request, false);
	}

	// additionally support simulation of an IP address for mobile GW usecase only
	public static String[] getGatewayIps(HttpServletRequest request) {
		var ip = getHeader(HTTP_HEADER_X_SIMULATED_FORWARDED_FOR, request);
		if (ip != null) {
			return new String[] { ip };
		}
		return getClientIps(request, false);
	}

	// Track problems based on IP addresses the user agents have (attacks, debugging login problems)
	public static String getGatewayIp(HttpServletRequest request, boolean tagged) {
		if (request == null) {
			return null; // testing only
		}
		var ips = getClientIps(request, tagged);
		if (ips.length > 0) {
			return ips[ips.length - 1]; // last entry is direct gateway calling us
		}
		return null;
	}

	public static String[] getClientIps(HttpServletRequest request, boolean tagged) {
		var ip = getHeader(HTTP_HEADER_X_ORIGINAL_FORWARDED_FOR, request);
		var tag = "XOFF"; // standard case behind a K8S nginx behind a layer-7 loadbalancer
		if (ip == null) {
			ip = getHeader(HTTP_HEADER_X_FORWARDED_FOR, request);
			tag = "XFF"; // standard case behind an OSI layer-7 loadbalancer
		}
		if (ip == null) {
			ip = getHeader(HTTP_HEADER_X_REAL_IP, request);
			tag = "RIP"; // Loadbalancer direct client IP
		}
		if (ip == null) {
			ip = request.getRemoteAddr();
			tag = "SRA"; // Our service direct client IP from the TCP socket
		}
		if (ip != null) {
			var ips = ip.split(", "); // X-Forwarded-For: client, proxy1, proxy2
			if (tagged) {
				for (int i = 0; i < ips.length; i++) {
					ips[i] = ips[i] + "/" + tag;
				}
			}
			return ips;
		}
		return new String[0];
	}

	public static String getServiceContext(HttpServletRequest request) {
		// not called from web
		if (request == null) {
			return "service='INTERNAL'";
		}
		// REST like GET/POST FQ-url
		var sb = new StringBuilder();
		sb.append("method='");
		sb.append(request.getMethod());
		sb.append("' url='");
		sb.append(request.getRequestURL());
		sb.append("'");
		return StringUtil.clean(sb.toString(), " ");
	}

	public static String getOrigin(HttpServletRequest request) {
		return request.getHeader(HttpHeaders.ORIGIN);
	}

	public static String getOriginOrReferer(HttpServletRequest request) {
		var origin = getOrigin(request);
		if (origin != null) {
			return origin;
		}
		var referer = getReferer(request);
		return getValidOrigin(referer);
	}

	public static String getReferer(HttpServletRequest request) {
		return request.getHeader(HttpHeaders.REFERER);
	}

	public static void addCookies(HttpServletResponse response, List<Cookie> cookies) {
		for (var cookie : cookies) {
			response.addCookie(cookie);
		}
	}

	public static String getUrlWithQuery(HttpServletRequest request) {
		var uri = request.getRequestURI();
		var query = request.getQueryString();
		if (query != null) {
			uri += '?' + query;
		}
		return uri;
	}

	public static String urlEncodeValue(String value) {
		if (value == null) {
			return "";
		}
		return URLEncoder.encode(value, StandardCharsets.UTF_8);
	}

	public static String urlDecodeValue(String value) {
		if (value == null) {
			return "";
		}
		return URLDecoder.decode(value, StandardCharsets.UTF_8);
	}

	public static String appendQueryParameters(String url, Map<String, String> parameters) {
		if (CollectionUtils.isEmpty(parameters)) {
			return url;
		}
		var urlBuilder = new StringBuilder(url != null ? url : "");
		var querySep = (url != null && url.indexOf('?') >= 0) ? '&' : '?';
		for (var parameter : parameters.entrySet()) {
			urlBuilder.append(querySep);
			urlBuilder.append(URLEncoder.encode(parameter.getKey(), StandardCharsets.UTF_8));
			urlBuilder.append('=');
			if (parameter.getValue() != null) {
				urlBuilder.append(URLEncoder.encode(parameter.getValue(), StandardCharsets.UTF_8));
			}
			querySep = '&';
		}
		return urlBuilder.toString();
	}

	public static Cookie createCookie(CookieParameters params) {
		log.debug("Generate cookie for params={}", params);
		var cookie = new Cookie(params.getName(), params.getValue());
		if (params.getMaxAge() != null && params.getMaxAge() != -1) {
			cookie.setMaxAge(params.getMaxAge()); // <0 is browser session, 0 is expired, >0 is max validity in seconds
		}
		if (StringUtils.isNotEmpty(params.getDomain())) {
			cookie.setDomain(params.getDomain());
		}
		cookie.setSecure(params.isSecure());
		cookie.setHttpOnly(params.isHttpOnly());
		if (StringUtils.isEmpty(params.getPath())) {
			cookie.setPath("/");
		}
		else {
			cookie.setPath(params.getPath());
		}
		if (params.getSameSite() != null) {
			if (isSameSiteDynamic(params.getSameSite())) {
				log.warn("Not setting internal value sameSite={} on cookie={}", params.getSameSite(), params.getName());
			}
			else {
				cookie.setAttribute(COOKIE_SAME_SITE, params.getSameSite());
			}
		}
		// SameSite=None is set by default via sameSiteCookiesConfig
		return cookie;
	}

	public static String getCookieSameSite(String perimeterUrl, String requestUrl) {
		var isSameSite = isSameSite(getValidatedUri(perimeterUrl), getValidatedUri(requestUrl));
		var sameSite = getSameSite(isSameSite);
		log.debug("Cookie sameSite={} for perimeterUrl={} requestUrl={}", sameSite, perimeterUrl, requestUrl);
		return sameSite;
	}

	/**
	 * @param isSameSite e.g. result of isSameSite(URI, URI)
	 * @return sameSite flag - has to be NONE if RPs that are cross site to XTB, STRICT if they are same site
	 * (LAX does not work in the former case for SAML posts, and is not as restrictive as possible in the latter case)
	 */
	public static String getSameSite(boolean isSameSite) {
		return isSameSite ? COOKIE_SAME_SITE_STRICT : COOKIE_SAME_SITE_NONE;
	}

	/**
	 * @param sameSiteConfig
	 * @return true if the config is null or has the special XTB value Dynamic
	 */
	public static boolean isSameSiteDynamic(String sameSiteConfig) {
		return sameSiteConfig == null || sameSiteConfig.equals(COOKIE_SAME_SITE_DYNAMIC);
	}

	/**
	 * @return true if URIs are not null, absolute, and same site (same site and same scheme, port does not matter)
	 * @see WebUtil#getSite(URI)
	 */
	public static boolean isSameSite(URI uri1, URI uri2) {
		if (uri1 == null || uri2 == null || uri1.getScheme() == null || uri2.getScheme() == null) {
			log.debug("Could not extract scheme from URI(s), not considered same site: uri1={}, uri2={}", uri1, uri2);
			return false;
		}
		if (!uri1.getScheme().equalsIgnoreCase(uri2.getScheme())) {
			return false;
		}
		var site1 = getSite(uri1);
		var site2 = getSite(uri2);
		if (site1 == null || site2 == null) {
			log.debug("Could not extract site from URI(s), not considered same site: uri1={}, uri2={}", uri1, uri2);
			return false;
		}
		return site1.equals(site2);
	}

	/**
	 * Site extraction based on InternetDomainName, returns the full host name if it cannot be extracted
	 * (e.g. for localhost, localdomain)
	 *
	 * @return site of URI with the restriction above or null if it cannot be extracted
	 * @see com.google.common.net.InternetDomainName
	 */
	public static String getSite(URI uri) {
		if (uri == null || uri.getHost() == null) {
			return null;
		}
		try {
			var domain = InternetDomainName.from(uri.getHost());
			var site = domain.topPrivateDomain();
			log.debug("Extracted site={} from uri={}", site, uri);
			return site.toString();
		}
		catch (IllegalStateException ex) {
			log.debug("Not a top level domain: uri={}", uri);
			return uri.getHost();
		}
	}

	public static URI getValidatedUri(String url) {
		if (url != null) {
			try {
				return new URI(url);
			}
			catch (URISyntaxException e) {
				log.warn("Failed to parse url={} exception={}", url, e.toString());
			}
		}
		return null;
	}

	public static String getUrlHost(String url) {
		return getFromValidUrl(url, URI::getHost, null);
	}

	public static boolean isValidAbsoluteUrl(String url) {
		return getFromValidUrl(url, URI::isAbsolute, false);
	}

	public static boolean isValidRelativeUrl(String url) {
		return getFromValidUrl(url, uri -> !uri.isAbsolute(), false);
	}

	private static <T> T getFromValidUrl(String url, Function<URI, T> getter, T defaultValue) {
		var uri = getValidatedUri(url);
		if (uri == null) {
			return defaultValue;
		}
		return getter.apply(uri);
	}

	// If otherUrl is already an absolute URI, use it. Else if baseUrl is an absolute URI use it to make otherUrl absolute
	public static String getAbsoluteUrl(String baseUrl, String otherUrl) {
		var otherUri = getValidatedUri(otherUrl);
		if (otherUri == null) {
			log.info("otherUrl={} not provided or not valid, using baseUrl={}", otherUrl, baseUrl);
			return baseUrl;
		}
		if (otherUri.isAbsolute()) {
			log.debug("otherUrl={} is already absolute, ignoring baseUrl={}", otherUrl, baseUrl);
			return otherUrl;
		}
		var baseUri = getValidatedUri(baseUrl);
		if (baseUri == null || !baseUri.isAbsolute()) {
			log.info("baseUrl={} not provided or not absolute, using relative otherUrl={}", baseUrl, otherUrl);
			return otherUrl;
		}
		var resultUrl = baseUri.resolve(otherUri).toString();
		log.debug("relative otherUri={} absolute baseUrl={} resulting in absoluteUrl={}", otherUrl, baseUrl, resultUrl);
		return resultUrl;
	}

	// Referer without path is scheme://host[:port]/
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer
	public static String getValidRefererWithoutPath(String referer) {
		var uri = getValidatedUri(referer);
		var origin = getValidOrigin(uri);
		if (origin == null) {
			return null;
		}
		return origin + '/';
	}

	// Origin is scheme://host[:port] or "null"
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin
	public static String getValidOrigin(String origin) {
		if (isNullOrigin(origin)) {
			// null is not recommended - maybe needed for hybrid mobile apps?
			// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
			log.info("Received valid origin={}", origin);
			return origin;
		}
		var uri = getValidatedUri(origin);
		return getValidOrigin(uri);
	}

	// Returns true if the origin is the special "null" value
	public static boolean isNullOrigin(String origin) {
		return "null".equals(origin);
	}

	// Convenience method if the origin was already parsed. "null" origin is not supported.
	public static String getValidOrigin(URI uri) {
		if (uri == null || uri.getScheme() == null || uri.getHost() == null) {
			return null;
		}
		var originBuilder = new StringBuilder().append(uri.getScheme())
											   .append("://")
											   .append(uri.getHost());
		if (uri.getPort() != -1) {
			originBuilder.append(':')
						 .append(uri.getPort());
		}
		return originBuilder.toString();
	}

	/**
	 * "etag" must contain leading and trailing quotes
	 *
	 * @see <a hef="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/ETag">ETag</a>
	 * @see <a hef="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control">Cache-Control</a>
	 * @see <a hef="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Expires">Expires</a>
	 * @see <a hef="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Pragma">Pragma</a>
	 */
	public static void addCacheHeaders(HttpServletResponse response, int maxAgeSecs, String etag, Instant lastModified,
			Instant now) {
		if (maxAgeSecs <= 0) {
			response.setHeader(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL_NO_CACHE);
			response.setHeader(HttpHeaders.PRAGMA, PRAGMA_NO_CACHE);
			response.setIntHeader(HttpHeaders.EXPIRES, 0);
		}
		else {
			response.setHeader(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL_MAX_AGE + maxAgeSecs);
			response.setHeader(HttpHeaders.PRAGMA, "");
			response.setHeader(HttpHeaders.EXPIRES, DateUtils.formatStandardDate(now.plusSeconds(maxAgeSecs)));
		}
		if (lastModified != null) {
			response.setHeader(HttpHeaders.LAST_MODIFIED, DateUtils.formatStandardDate(lastModified));
		}
		if (etag != null) {
			response.setHeader(HttpHeaders.ETAG, etag);
		}
	}

	/**
	 * Returns true if the resource has not been modified based on the browser headers If-None-Match/If-Modified-Since.
	 * "etag" must contain leading and trailing quotes
	 *
	 * @see <a hef="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/If-None-Match">If-None-Match</a>
	 * @see <a hef="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/If-Modified-Since">If-Modified-Since</a>
	 */
	public static boolean isCached(String etag, String ifNoneMatch, Instant cacheTime, String ifModifiedSince) {
		if (etag != null && ifNoneMatch != null && ifNoneMatch.contains(etag)) {
			return true;
		}
		if (cacheTime != null && ifModifiedSince != null) {
			var browserCacheTime = DateUtils.parseStandardDate(ifModifiedSince);
			return browserCacheTime != null && !browserCacheTime.isBefore(cacheTime);
		}
		return false;
	}

	/**
	 * Validate origin/referer against allow list.
	 * @param allowedUrls allowed URLs (AC whitelist etc.)
	 * @param originOrReferer original URL from request
	 * @param validatedOriginOrReferer optional validated variant from <code>getValidOrigin</code> or <code>getValidatedUri</code>
	 * @return true if the URL is in the allowed list, ignoring the path (which origin would not have, and for referer we do
	 * not care about).
	 */
	public static boolean isAllowedOriginOrReferer(Collection<String> allowedUrls, String originOrReferer,
			String validatedOriginOrReferer) {
		var allowedUrlSet = CollectionUtil.collectionAsSet(allowedUrls);
		return UrlAcceptor.isTrustedOrigin(validatedOriginOrReferer, allowedUrlSet) ||
				UrlAcceptor.isTrustedOrigin(originOrReferer, allowedUrlSet);
	}

	private static boolean isOriginOrRefererInSets(Collection<Collection<String>> allowedUrlSets,
			String originOrReferer, String validatedOriginOrReferer) {
		for (var allowedUrls : allowedUrlSets) {
			if (isAllowedOriginOrReferer(allowedUrls, originOrReferer, validatedOriginOrReferer)) {
				return true;
			}
		}
		return false;
	}

	// convenience method with multiple sets of URLs
	public static boolean isAllowedOrigin(Collection<Collection<String>> allowedUrlSets, String origin) {
		var validOrigin = getValidOrigin(origin);
		return isOriginOrRefererInSets(allowedUrlSets, origin, validOrigin);
	}

	// convenience method with multiple sets of URLs
	public static boolean isAllowedReferer(Collection<Collection<String>> allowedUrlSets, String referer) {
		var validReferer = Objects.toString(getValidatedUri(referer), null);
		return isOriginOrRefererInSets(allowedUrlSets, referer, validReferer);
	}

}
