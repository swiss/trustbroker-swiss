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

package swiss.trustbroker.oidc.tx;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.doReturn;

import java.util.function.BiConsumer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.OidcFrameAncestorHandler;
import swiss.trustbroker.util.ApiSupport;

class OidcTxResponseWrapperTest {

	private TrustBrokerProperties properties;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	@Mock
	private OidcFrameAncestorHandler oidcFrameAncestorHandler;

	@Mock
	private ApiSupport apiSupport;

	@Mock
	private RelyingPartyDefinitions definitions;

	private OidcTxResponseWrapper oidcTxResponseWrapper;

	@BeforeEach
	void setUp() {
		MockitoAnnotations.openMocks(this);
		properties = new TrustBrokerProperties();
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
		oidcTxResponseWrapper = new OidcTxResponseWrapper(request, response, definitions, properties, apiSupport,
				oidcFrameAncestorHandler);
	}

	@Test
	void addHeaderFrameOptions() {
		testFrameOptions(oidcTxResponseWrapper::addHeader);
	}

	@Test
	void setHeaderFrameOptions() {
		testFrameOptions(oidcTxResponseWrapper::setHeader);
	}

	private	void testFrameOptions(BiConsumer<String, String> testMethod) {
		testMethod.accept(XFrameOptionsHeaderWriter.XFRAME_OPTIONS_HEADER,
				XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name());
		assertThat(response.getHeader(XFrameOptionsHeaderWriter.XFRAME_OPTIONS_HEADER),
				is(XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN.name()));
		// other header unchanged
		oidcTxResponseWrapper.addHeader(HttpHeaders.PRAGMA,
				XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name());
		assertThat(response.getHeader(HttpHeaders.PRAGMA),
				is(XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name()));
	}

	@Test
	void addHeaderFrameOptionsWithAllowedOrigins() {
		frameOptionsDropped(oidcTxResponseWrapper::addHeader);
	}

	@Test
	void setHeaderFrameOptionsWithAllowedOrigins() {
		frameOptionsDropped(oidcTxResponseWrapper::setHeader);
	}

	private void frameOptionsDropped(BiConsumer<String, String> testMethod) {
		// frame options dropped
		doReturn(true).when(oidcFrameAncestorHandler).hasAppliedFrameAncestors();
		testMethod.accept(XFrameOptionsHeaderWriter.XFRAME_OPTIONS_HEADER,
				XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name());
		assertThat(response.getHeader(XFrameOptionsHeaderWriter.XFRAME_OPTIONS_HEADER), is(nullValue()));
	}

}
