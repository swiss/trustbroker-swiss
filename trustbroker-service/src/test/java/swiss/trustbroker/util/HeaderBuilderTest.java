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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.config.TrustBrokerProperties;

class HeaderBuilderTest implements FrameAncestorHandler {

	private static final String FRAME_OPTIONS = "DENY";

	private static final String CSP = "default-src https://localhost";

	public static final String ACL = "https://localhost:8080";

	public static final String OWN_URL = "https://localhost:9090";

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private TrustBrokerProperties properties;

	private HeaderBuilder headerBuilder;

	private List<String> frameAncestors;

	private List<String> appliedFrameAncestors;

	@BeforeEach
	void setup() {
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
		properties = new TrustBrokerProperties();
		frameAncestors = Collections.emptyList();
		headerBuilder = HeaderBuilder.of(request, response, properties, this);
	}

	@Test
	void hsts() {
		headerBuilder.hsts();
		assertThat(response.getHeader(HeaderBuilder.STRICT_TRANSPORT_SECURITY), is(not(nullValue())));
	}

	@Test
	void hstsUnsecure() {
		properties.setSecureBrowserHeaders(false);
		headerBuilder.hsts();
		assertThat(response.getHeader(HeaderBuilder.STRICT_TRANSPORT_SECURITY), is(nullValue()));
	}

	@Test
	void robotsTag() {
		headerBuilder.robotsTag();
		assertThat(response.getHeader(HeaderBuilder.ROBOTS_TAG), is(not(nullValue())));
	}

	@Test
	void referrerPolicy() {
		headerBuilder.referrerPolicy();
		assertThat(response.getHeader(HeaderBuilder.REFERRER_POLICY), is(not(nullValue())));
	}

	@Test
	void contentTypeOptions() {
		headerBuilder.contentTypeOptions();
		assertThat(response.getHeader(HeaderBuilder.CONTENT_TYPE_OPTIONS), is(not(nullValue())));
	}

	@Test
	void defaultCsp() {
		properties.getCsp().setFallback(CSP);
		headerBuilder.defaultCsp();
		assertThat(response.getHeader(HeaderBuilder.CONTENT_SECURITY_POLICY), is(CSP));
	}

	@Test
	void samlCsp() {
		properties.getCsp().setSaml(CSP);
		headerBuilder.samlCsp();
		assertThat(response.getHeader(HeaderBuilder.CONTENT_SECURITY_POLICY), is(CSP));
	}

	@Test
	void frontendCsp() {
		properties.getCsp().setFrontend(CSP);
		headerBuilder.frontendCsp();
		assertThat(response.getHeader(HeaderBuilder.CONTENT_SECURITY_POLICY), is(CSP));
	}

	@Test
	void defaultFrameOptions() {
		properties.getFrameOptions().setFallback(FRAME_OPTIONS);
		headerBuilder.defaultFrameOptions();
		assertThat(response.getHeader(HeaderBuilder.FRAME_OPTIONS), is(FRAME_OPTIONS));
	}

	@ParameterizedTest
	@MethodSource
	void oidcCspFrameOptions(List<String> frameAncestors, String origin, String referer,
			String frameOptions, Set<String> ownOrigins,  String expectedFrameOptions, String csp, String expectedCsp,
			List<String> expectedAppliedFrameAncestors) {
		properties.getCsp().setOidc(csp);
		properties.getFrameOptions().setOidc(frameOptions);
		if (origin != null) {
			request.addHeader(HttpHeaders.ORIGIN, origin);
		}
		if (referer != null) {
			request.addHeader(HttpHeaders.REFERER, referer);
		}
		this.frameAncestors = frameAncestors;
		headerBuilder.oidcCspFrameOptions(ownOrigins);
		assertThat(response.getHeader(HeaderBuilder.CONTENT_SECURITY_POLICY), is(expectedCsp));
		assertThat(response.getHeader(HeaderBuilder.FRAME_OPTIONS), is(expectedFrameOptions));
		assertThat(appliedFrameAncestors, is(expectedAppliedFrameAncestors));
	}

	static Object[][] oidcCspFrameOptions() {
		var aclCsp = CSP + "; frame-ancestors 'self' " + ACL;
		return new Object[][] {
				{ Collections.emptyList(), null, null, null, Collections.emptySet(),
						null, CSP, CSP, Collections.emptyList() },
				{ Collections.emptyList(), null, null, FRAME_OPTIONS, Collections.emptySet(),
						FRAME_OPTIONS, CSP, CSP, Collections.emptyList() },
				{ List.of(ACL), null, null, "SAMEORIGIN", Collections.emptySet(),
						"SAMEORIGIN", CSP, CSP, Collections.emptyList() },
				{ List.of(ACL), ACL, null, FRAME_OPTIONS, Collections.emptySet(),
						null, CSP, aclCsp, List.of(ACL) },
				{ List.of(CorsSupport.ALL_ORIGINS), ACL, null, FRAME_OPTIONS, Collections.emptySet(),
						null, CSP, aclCsp, List.of(ACL) },
				{ List.of(ACL), null, ACL + "/path", FRAME_OPTIONS, Collections.emptySet(),
						null, CSP, aclCsp, List.of(ACL) },
				{ List.of(ACL), ACL, null, FRAME_OPTIONS, Collections.emptySet(),
						null, CSP, aclCsp, List.of(ACL) },
				{ List.of(ACL), ACL, null, FRAME_OPTIONS, Collections.emptySet(),
						null, null, "frame-ancestors 'self' " + ACL, List.of(ACL) },
				{ List.of(ACL), OWN_URL, null, FRAME_OPTIONS, Set.of(OWN_URL),
						null, null, "frame-ancestors 'self' " + OWN_URL, List.of(OWN_URL) }

		};
	}

	@Override
	public List<String> supportedFrameAncestors() {
		return frameAncestors;
	}

	@Override
	public void appliedFrameAncestors(List<String> appliedFrameAncestors) {
		this.appliedFrameAncestors = appliedFrameAncestors;
	}
}
