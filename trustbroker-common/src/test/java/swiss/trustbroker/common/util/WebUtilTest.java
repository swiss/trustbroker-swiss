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

package swiss.trustbroker.common.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.servlet.http.Cookie;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hc.client5.http.utils.DateUtils;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.common.dto.CookieParameters;
import swiss.trustbroker.common.exception.TechnicalException;

class WebUtilTest {

	private static final String TEST_URL = "https://localhost";

	private static final String TEST_QUERY = "one=uno&two=due&three=tre&two=deux";

	private static final String TEST_URL_WITH_QUERY = TEST_URL + '?' + TEST_QUERY;

	@Test
	void getUrlWithQuery() {
		var request = new MockHttpServletRequest();
		request.setRequestURI(TEST_URL);
		assertThat(WebUtil.getUrlWithQuery(request), is(TEST_URL));
		request.setQueryString(TEST_QUERY);
		assertThat(WebUtil.getUrlWithQuery(request), is(TEST_URL_WITH_QUERY));
	}

	@ParameterizedTest
	@CsvSource(value = {
			",''",
			"https://localhost,https%3A%2F%2Flocalhost"
	})
	void testUrlEncodeValue(String url, String expected) {
		assertThat(WebUtil.urlEncodeValue(url), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			",''",
			"https%3A%2F%2Flocalhost,https://localhost"
	})
	void testUrlDecodeValue(String url, String expected) {
		assertThat(WebUtil.urlDecodeValue(url), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"https%3A%2F%2Flocalhost,https%3A%2F%2Flocalhost",
			"https%3a%2f%2flocalhost,https%3A%2F%2Flocalhost"
	})
	void testUrlDecodeEncodeValue(String url, String expected) {
		assertThat(WebUtil.urlEncodeValue(WebUtil.urlDecodeValue(url)), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			",false,false",
			"'',false,true",
			"/path,false,true",
			"http://localhost:1234/return/to?x=y,true,false",
			"myapp://launch,true,false",
	})
	void testIsValidRelativeAbsoluteUrl(String url, boolean absolute, boolean relative) {
		assertThat(WebUtil.isValidAbsoluteUrl(url), is(absolute));
		assertThat(WebUtil.isValidRelativeUrl(url), is(relative));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null",
			"https://example.trustbroker.swiss:8080/path?query=123,example.trustbroker.swiss",
			"https:localhost/bla,null"
	}, nullValues = "null")
	void testUrlHost(String url, String expected) {
		assertThat(WebUtil.getUrlHost(url), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"http://localhost/test,http://localhost",
			"https://test.trustbroker.swiss:443/test,https://test.trustbroker.swiss:443",
			"some,null"
	}, nullValues = "null")
	void testOrigin(String url, String expected) {
		var request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.REFERER, url);
		assertThat(WebUtil.getOriginOrReferer(request), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"NULL,false",
			"null,true",
			"https://localhost,false"
	}, nullValues = "NULL")
	void isNullOrigin(String origin, boolean expected) {
		assertThat(WebUtil.isNullOrigin(origin), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			// missing base or other
			"null,null,null",
			"null,/test,/test",
			"https://example.trustbroker.swiss,null,https://example.trustbroker.swiss",
			"null,https://example.trustbroker.swiss/test,https://example.trustbroker.swiss/test",
			// absolute other
			"https://example.trustbroker.swiss,https://localhost:8080/test,https://localhost:8080/test",
			"/base,https://localhost:8080/test,https://localhost:8080/test",
			// relative other, absolute base
			"https://example.trustbroker.swiss,/test,https://example.trustbroker.swiss/test",
			// relative base and other
			"/base,/test,/test"
	}, nullValues = "null")
	void testGetAbsoluteUrl(String baseUrl, String otherUrl, String expectedResult) {
		assertThat(WebUtil.getAbsoluteUrl(baseUrl, otherUrl), is(expectedResult));
	}

	@ParameterizedTest
	@MethodSource
	void testAppendQueryParameters(String query, Map<String, String> parameters, String expected) {
		assertThat(WebUtil.appendQueryParameters(query, parameters), is(expected));
	}

	static Object[][] testAppendQueryParameters() {
		// ensure predictable iteration order for the test
		var paramMap1 = new LinkedHashMap<String, String>();
		paramMap1.put("key1", "value1");
		paramMap1.put("key+", "this&that");

		var paramMap2 = new LinkedHashMap<String, String>();
		paramMap2.put("a", "");
		paramMap2.put("b", null);

		return new Object[][] {
				{ null, null, null },
				{ null, paramMap2, "?a=&b=" },
				{ TEST_URL, Collections.emptyMap(), TEST_URL },
				{ "https://localhost/test", paramMap1, "https://localhost/test?key1=value1&key%2B=this%26that" },
				{ "https://localhost/test?foo=bar", paramMap2, "https://localhost/test?foo=bar&a=&b=" }
		};
	}

	@ParameterizedTest
	@MethodSource
	void testSplitQueryParameters(String url, boolean encodeParams, String expectedUrl,
			List<Pair<String, String>> expectedParams) {
		var result = WebUtil.splitQueryParameters(url, encodeParams);
		assertThat(result.getKey(), is(expectedUrl));
		assertThat(result.getValue(), is(expectedParams));
	}

	static Object[][] testSplitQueryParameters() {
		return new Object[][] {
				{ null, true, null, Collections.emptyList() },
				{ "invalid", true, "invalid", Collections.emptyList() },
				{ TEST_URL + "?a=b&c=d%22e", false, TEST_URL, List.of(
						Pair.of("a", "b"), Pair.of("c", "d\"e")
				) },
				{ TEST_URL + "?a&q%22=x%22y&c=d&c=f", true, TEST_URL, List.of(
						Pair.of("a", null), Pair.of("q&quot;", "x&quot;y"),
						Pair.of("c", "d"), Pair.of("c", "f")
				) }
		};
	}

	@ParameterizedTest
	@CsvSource(
			value = {
					"null,null",
					",", // empty URL accepted
					"url?param?,url", // invalid URL accepted
					"http://localhost:1234/path/to/file?query=param&query=param,http://localhost:1234/path/to/file"
			}, nullValues = "null"
	)
	void testRemoveQueryParameters(String url, String expectedUrl) {
		assertThat(WebUtil.removeQueryParameters(url), is(expectedUrl));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"persistentCookie,sessionId1,300,true,true,domain.org,/foo,null,persistentCookie,sessionId1,300,true,true,domain.org,/foo,null",
			"sessionCookie,sessionId2,null,false,false,null,null,Lax,sessionCookie,sessionId2,-1,false,false,null,/,Lax",
			"sessionCookie,sessionId2,-1,false,false,null,,Strict,sessionCookie,sessionId2,-1,false,false,null,/,Strict",
			"sessionCookie,sessionId2,-1,false,false,,/path/to/app,None,sessionCookie,sessionId2,-1,false,false,null,/path/to/app,None",
			"sessionCookie,sessionId2,-1,false,false,,/path,Dynamic,sessionCookie,sessionId2,-1,false,false,null,/path,null"
	}, nullValues = "null")
	void testCreateCookie(String name, String sessionId, Integer lifeTime, boolean secure, boolean httpOnly, String domain,
			String path, String sameSite, String expectedName, String expectedSessionId, Integer expectedLifeTime,
			boolean expectedSecure, boolean expectedHttpOnly, String expectedDomain, String expectedPath, String expectedSameSite) {
		var params = CookieParameters.builder()
									 .name(name)
									 .value(sessionId)
									 .maxAge(lifeTime)
									 .secure(secure)
									 .httpOnly(httpOnly)
									 .domain(domain)
									 .path(path)
									 .sameSite(sameSite)
									 .build();
		var cookie = WebUtil.createCookie(params);
		assertThat(cookie.getName(), is(expectedName));
		assertThat(cookie.getValue(), is(expectedSessionId));
		assertThat(cookie.getMaxAge(), is(expectedLifeTime));
		assertThat(cookie.getSecure(), is(expectedSecure));
		assertThat(cookie.isHttpOnly(), is(expectedHttpOnly));
		assertThat(cookie.getDomain(), is(expectedDomain));
		assertThat(cookie.getPath(), is(expectedPath));
		assertThat(cookie.getAttribute(WebUtil.COOKIE_SAME_SITE), is(expectedSameSite));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null", // special origin value
			"NULL,NULL",
			",NULL",
			"foobar,NULL",
			"https://example.trustbroker.swiss,https://example.trustbroker.swiss",
			"https://example.trustbroker.swiss/,https://example.trustbroker.swiss",
			"https://example.trustbroker.swiss/path?query=value#fragment,https://example.trustbroker.swiss",
			"https://example.trustbroker.swiss:443,https://example.trustbroker.swiss:443",
			"custom://value,custom://value",
			"http://localhost:8080,http://localhost:8080"
	}, nullValues = "NULL") // capital on purpose due to null origin value
	void testGetValidOrigin(String origin, String expected) {
		assertThat(WebUtil.getValidOrigin(origin), CoreMatchers.is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,NULL", // special origin value ignored
			"NULL,NULL",
			",NULL",
			"foobar,NULL",
			"https://example.trustbroker.swiss,https://example.trustbroker.swiss/",
			"https://example.trustbroker.swiss/,https://example.trustbroker.swiss/",
			"https://example.trustbroker.swiss/path?query=value#fragment,https://example.trustbroker.swiss/",
			"https://example.trustbroker.swiss:443,https://example.trustbroker.swiss:443/",
			"custom://value,custom://value/",
			"http://localhost:8080,http://localhost:8080/"
	}, nullValues = "NULL") // capital on purpose due to null referer value
	void testGetValidRefererWithoutPath(String referer, String expected) {
		assertThat(WebUtil.getValidRefererWithoutPath(referer), CoreMatchers.is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null",
			"/path,null", // relative
			"://,null", // invalid
			"https://trustbroker.swiss,trustbroker.swiss",
			"https://sub.domain.trustbroker.swiss,trustbroker.swiss",
			"https://trustbroker.ch,trustbroker.ch",
			"https://test.trustbroker.ch,trustbroker.ch", // domain not under control of trustbroker.swiss
			"http://trustbroker.swiss:8080/test,trustbroker.swiss",
			"http://localhost/path,localhost", // extraction not implemented
			"http://sub.localhost.localdomain/path,sub.localhost.localdomain", // extraction not implemented
			"http://sub.trustbroker.co.uk/path,trustbroker.co.uk" // domain not under control of trustbroker.swiss
	}, nullValues = "null")
	void testGetSite(String url, String expected) {
		var uri = WebUtil.getValidatedUri(url);
		var result = WebUtil.getSite(uri);
		assertThat(result, is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,false",
			"https://trustbroker.swiss,null,false",
			"null,https://trustbroker.swiss,false",
			"Https://TrustBroker.swiss/Path1,HTTPS://TRUSTBROKER.SWISS/PATH2,true", // case is irrelevant
			"https://trustbroker.swiss/path1,https://trustbroker.swiss/path2,true",
			"https://trustbroker.swiss/path1,http://trustbroker.swiss/path2,false", // scheme mismatch
			"https://sub.one.trustbroker.swiss/path1,https://sub.two.trustbroker.swiss/path2,true",
			"http://localhost/path,https://localhost/test,false", // scheme mismatch
			"https://localhost/path,https://localhost:9090/test,true", // extraction not implemented
			"http://one.trustbroker.co.uk/a,http://two.trustbroker.co.uk/b,true" // domain not under control of trustbroker.swiss
			// not repeating all the extraction cases covered by testGetSite
	}, nullValues = "null")
	void testIsSameSite(String url1, String url2, boolean expected) {
		var uri1 = WebUtil.getValidatedUri(url1);
		var uri2 = WebUtil.getValidatedUri(url2);
		var result = WebUtil.isSameSite(uri1, uri2);
		assertThat(result, is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,",
			"cross-site,true",
			"same-site,false",
			"same-origin,false",
			"none,false"
	}, nullValues = "null")
	void testIsCrossSiteRequest(String secFetchMode, Boolean  expected) {
		var request = new MockHttpServletRequest();
		if (secFetchMode != null) {
			request.addHeader(WebUtil.HTTP_HEADER_SEC_FETCH_SITE, secFetchMode);
		}
		var result = WebUtil.isCrossSiteRequest(request);
		assertThat(result, is(Optional.ofNullable(expected)));
	}

	@ParameterizedTest
	@CsvSource(value = {
			// test default usually Lax as this is never returned otherwise
			"null,null,null,null,null,null", // nothing set
			// default wins:
			"Lax,null,null,null,null,Lax",
			"Lax,null,null,false,false,Lax",
			"None,null,null,null,false,None",
			"Dynamic,null,null,null,null,Strict", // winning default dynamic adapted
			"Lax,null,null,true,null,None", // cross-site true wins
			"None,null,null,null,true,null", // insecure override
			"Lax,null,https://localhost,null,null,None", // no perimeter
			"Lax,https://foo.trustbroker.swiss/path1,https://localhost,null,null,None", // cross-site
			"Lax,https://foo.trustbroker.swiss/path1,https://bar.trustbroker.swiss/path2,null,null,Strict", // same site
			"Lax,https://foo.trustbroker.swiss/path1,https://bar.trustbroker.swiss/path2,true,null,None" // cross-site true wins
	}, nullValues = "null")
	void testGetCookieSameSite(String defaultValue, String perimeterUrl, String requestUrl, Boolean crossSiteRequest,
			Boolean insecureRequest, String expected) {
		var result = WebUtil.getCookieSameSite(defaultValue, perimeterUrl, requestUrl, Optional.ofNullable(crossSiteRequest),
				Optional.ofNullable(insecureRequest));
		assertThat(result, is(expected));
	}

	@Test
	void testDeduplicateSetCookie() {
		Map<String, List<Cookie>> addedCookies = new HashMap<>();
		var cookie = WebUtil.createCookie(CookieParameters.builder()
														  .name("test")
														  .path("/test")
														  .value("val1")
														  .domain("localhost")
														  .build());
		var result = WebUtil.deduplicateSetCookie(addedCookies, cookie);
		assertThat(result.orElse(null), is(cookie));
		result = WebUtil.deduplicateSetCookie(addedCookies, cookie);
		assertTrue(result.isEmpty());
		var cookieCleared = WebUtil.createCookie(CookieParameters.builder()
														  .name("test")
														  .path("/test")
														  .value("")
														  .domain("localhost")
														  .build());
		result = WebUtil.deduplicateSetCookie(addedCookies, cookieCleared);
		assertThat(result.orElse(null), is(cookieCleared));
		var cookieChangedPath = WebUtil.createCookie(CookieParameters.builder()
																 .name("test")
																 .path("/test/sub")
																 .value("val2")
																 .domain("localhost")
																 .build());
		result = WebUtil.deduplicateSetCookie(addedCookies, cookieChangedPath);
		assertThat(result.orElse(null), is(cookieChangedPath));
		var otherCookie = WebUtil.createCookie(CookieParameters.builder()
													   .name("test2")
													   .path("/test")
													   .value("val1")
														.domain("localhost")
													   .build());
		result = WebUtil.deduplicateSetCookie(addedCookies, otherCookie);
		assertThat(result.orElse(null), is(otherCookie));
	}

	@Test
	void testCookieToString() {
		var name = "testName";
		var path = "/test";
		var value = "val1";
		var domain = "localhost";
		var cookie = WebUtil.createCookie(CookieParameters.builder()
														  .name(name)
														  .path(path)
														  .value(value)
														  .secure(true)
														  .httpOnly(true)
														  .domain(domain)
														  .sameSite(WebUtil.COOKIE_SAME_SITE_LAX)
														  .build());
		var cookies = WebUtil.cookiesToStrings(List.of(cookie));
		assertThat(cookies, hasSize(1));
		for (var check : new String[] { name, path, value, domain,
				// boolean flags only stored if true, with empty value (implementation detail of Cookie class, subject to change)
				WebUtil.COOKIE_SAME_SITE + '=' + WebUtil.COOKIE_SAME_SITE_LAX, "HttpOnly=", "Secure="
		}) {
			assertThat(cookies.getFirst(), containsString(check));
		}
	}

	@Test
	void testClientIp() {
		var singleIp = new MockHttpServletRequest();
		singleIp.addHeader(WebUtil.HTTP_HEADER_X_ORIGINAL_FORWARDED_FOR, "10.0.0.1");
		assertThat(WebUtil.getClientIp(singleIp), is("10.0.0.1/XOFF"));

		var proxyIps = new MockHttpServletRequest();
		proxyIps.addHeader(WebUtil.HTTP_HEADER_X_ORIGINAL_FORWARDED_FOR, "10.0.0.1, 10.0.0.2");
		assertThat(WebUtil.getClientIp(proxyIps, false), is("10.0.0.1"));

		var gatewayIp = new MockHttpServletRequest();
		gatewayIp.addHeader(WebUtil.HTTP_HEADER_X_ORIGINAL_FORWARDED_FOR, "10.0.0.1, 10.0.0.2");
		assertThat(WebUtil.getGatewayIp(gatewayIp), is("10.0.0.2"));
		assertThat(WebUtil.getGatewayIps(gatewayIp), is(List.of("10.0.0.1", "10.0.0.2")
															.toArray()));
		// override with simulation
		gatewayIp.addHeader(WebUtil.HTTP_HEADER_X_SIMULATED_FORWARDED_FOR, "10.0.0.3");
		assertThat(WebUtil.getGatewayIps(gatewayIp), is(List.of("10.0.0.3")
															.toArray()));
		assertThat(WebUtil.getClientIps(gatewayIp, false), is(List.of("10.0.0.1", "10.0.0.2")
																  .toArray()));

		var noIp = new MockHttpServletRequest();
		assertThat(WebUtil.getGatewayIp(noIp), is("127.0.0.1"));
		assertThat(WebUtil.getClientIp(noIp), is("127.0.0.1/SRA"));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,0,0,1000",
			"\"E199\",500,60,1000"
	}, nullValues = "null")
	void testAddCacheHeaders(String etag, int lastModifiedSecs, int maxAgeSecs, int nowSecs) {
		var response = new MockHttpServletResponse();
		var lastModified = Instant.ofEpochSecond(lastModifiedSecs);
		var expectedLastModified = lastModified != null ? DateUtils.formatStandardDate(lastModified) : null;
		var expectedPragma = maxAgeSecs > 0 ? "" : WebUtil.PRAGMA_NO_CACHE;
		var now = Instant.ofEpochSecond(nowSecs);
		var expires = Instant.ofEpochSecond(nowSecs + maxAgeSecs);
		var expectedExpires = maxAgeSecs == 0 ? "0" : DateUtils.formatStandardDate(expires);
		var expectedCacheControl = maxAgeSecs == 0 ? WebUtil.CACHE_CONTROL_NO_CACHE : WebUtil.CACHE_CONTROL_MAX_AGE + maxAgeSecs;

		WebUtil.addCacheHeaders(response, maxAgeSecs, etag, lastModified, now);

		assertThat(response.getHeader(HttpHeaders.ETAG), is(etag));
		assertThat(response.getHeader(HttpHeaders.LAST_MODIFIED), is(expectedLastModified));
		assertThat(response.getHeader(HttpHeaders.PRAGMA), is(expectedPragma));
		assertThat(response.getHeader(HttpHeaders.EXPIRES), is(expectedExpires));
		assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL), is(expectedCacheControl));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null;null;0;0;false",
			"\"E20AB\";\"B123\",\"E20AB\";0;0;true", // etag match
			"\"E20AB\";\"B123\",\"E20AB\";1000;100;true", // etag match wins
			"\"E20AB\";null;100;200;true", // modified since match
			"null;\"E20AB\";100;50;false", // modified since mismatch
	}, nullValues = "null", delimiter = ';')
	void testIsCached(String etag, String ifNoneMatch, int cacheTimeSecs, int ifModifiedSinceSecs, boolean expected) {
		var cacheTime = Instant.ofEpochSecond(cacheTimeSecs);
		var modified = Instant.ofEpochSecond(ifModifiedSinceSecs);
		var ifModifiedSince = ifModifiedSinceSecs == 0 ? null : DateUtils.formatStandardDate(modified);

		assertThat(WebUtil.isCached(etag, ifNoneMatch, cacheTime, ifModifiedSince), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,false",
			"navigate,http://other.localhost,false", // origin not checked
			"cors,https://localhost:8080/test,true", // origin not checked
			"null,http://other.localhost,true",
			"null,https://localhost:8080/path,false",
	}, nullValues = "null")
	void testIsCorsRequest(String secFetchMode, String origin, boolean expected) {
		var request = new MockHttpServletRequest();
		if (secFetchMode != null) {
			request.addHeader(WebUtil.HTTP_HEADER_SEC_FETCH_MODE, secFetchMode);
		}
		if (origin != null) {
			request.addHeader(HttpHeaders.ORIGIN, origin);
		}
		var requestUri = "https://localhost:8080/test";
		mockRequestUri(request, requestUri);

		assertThat(WebUtil.isCorsRequest(request), is(expected));
	}

	private static void mockRequestUri(MockHttpServletRequest request, String requestUri) {
		var uri = WebUtil.getValidatedUri(requestUri);
		request.setRequestURI(requestUri);
		request.setScheme(uri.getScheme());
		request.setServerName(uri.getHost());
		request.setServerPort(uri.getPort());
	}

	@ParameterizedTest
	@CsvSource(value = {
			"trustbroker.swiss,secret:1,Basic dHJ1c3Ricm9rZXIuc3dpc3M6c2VjcmV0OjE=",
			"client,1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890,Basic Y2xpZW50OjEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA="
	})
	void testGetBasicAuthorizationHeader(String clientId, String secret, String expected) {
		assertThat(WebUtil.getBasicAuthorizationHeader(clientId, secret), CoreMatchers.is(expected));
	}

	@Test
	void testGetBasicAuthorizationHeaderInvalid() {
		assertThrows(TechnicalException.class,
				() -> WebUtil.getBasicAuthorizationHeader(null, "any"));
		assertThrows(TechnicalException.class,
				() -> WebUtil.getBasicAuthorizationHeader("any", null));
		assertThrows(TechnicalException.class,
				() -> WebUtil.getBasicAuthorizationHeader("https://trustbroker.swiss/client","any"));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"token,Bearer token",
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890,Bearer 1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
	})
	void testGetBearerAuthorizationHeader(String token, String expected) {
		assertThat(WebUtil.getBearerAuthorizationHeader(token), CoreMatchers.is(expected));
	}
}
