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

package swiss.trustbroker.homerealmdiscovery.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.time.Instant;

import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.utils.DateUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.GuiProperties;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest
@ContextConfiguration(classes = { WebResourceProvider.class })
class WebResourceProviderTest {

	private static final String TRANSLATIONS = "cache/translations";

	private static final String ASSETS = "cache/assets";

	private static final String IMAGES = "cache/images";

	private GuiProperties gui;

	@MockitoBean
	private TrustBrokerProperties properties;

	@Autowired
	private WebResourceProvider resourceProvider;

	@BeforeEach
	void setUp() {
		gui = new GuiProperties();
		gui.setTaggedResourceMaxAgeSec(60);
		when(properties.getGui()).thenReturn(gui);
	}

	@AfterEach
	void tearDown() {
		resourceProvider.flushCache();
		assertThat(resourceProvider.cacheSize(), is(0));
	}

	@Test
	void getImageByNameWithMediaType() {
		var request = new MockHttpServletRequest();
		var response = new MockHttpServletResponse();
		var directory = SamlTestBase.fileFromClassPath(IMAGES).getAbsolutePath();
		gui.setImages(directory);

		resourceProvider.getImageByNameWithMediaType(request, response, "Empty.svg");

		assertOkResponse(response, WebResourceProvider.CONTENT_TYPE_SVG);
		assertThat(resourceProvider.cacheSize(), is(1));

		// response from cache
		request.addHeader(HttpHeaders.IF_NONE_MATCH, response.getHeader(HttpHeaders.ETAG));
		response = new MockHttpServletResponse();

		resourceProvider.getImageByNameWithMediaType(request, response, "Empty.svg");

		assertNotModifiedResponse(response);
		assertThat(resourceProvider.cacheSize(), is(1));
	}

	@Test
	void getThemeAsset() {
		var request = new MockHttpServletRequest();
		var response = new MockHttpServletResponse();
		var directory = SamlTestBase.fileFromClassPath(ASSETS).getAbsolutePath();
		gui.setThemeAssets(directory);

		resourceProvider.getThemeAsset(request, response, "styles.css");

		assertOkResponse(response, "text/css");
		assertThat(resourceProvider.cacheSize(), is(1));

		// response from cache
		request.addHeader(HttpHeaders.IF_MODIFIED_SINCE, DateUtils.formatStandardDate(Instant.now().plusSeconds(1)));
		response = new MockHttpServletResponse();

		resourceProvider.getThemeAsset(request, response, "styles.css");

		assertNotModifiedResponse(response);
		assertThat(resourceProvider.cacheSize(), is(1));
	}


	@Test
	void getTranslationForLanguage() {
		var request = new MockHttpServletRequest();
		var response = new MockHttpServletResponse();
		var directory = SamlTestBase.fileFromClassPath(TRANSLATIONS).getAbsolutePath();
		gui.setTranslations(directory);
		gui.setDefaultLanguage("en");

		resourceProvider.getTranslationForLanguage(request, response, "de");

		assertThat(resourceProvider.cacheSize(), is(1));
		assertOkResponse(response, MediaType.APPLICATION_JSON_VALUE);
		assertThat(resourceProvider.cacheSize(), is(1));

		// response from cache
		request.addHeader(HttpHeaders.IF_NONE_MATCH, response.getHeader(HttpHeaders.ETAG));
		request.addHeader(HttpHeaders.IF_MODIFIED_SINCE, DateUtils.formatStandardDate(Instant.now()));
		response = new MockHttpServletResponse();

		resourceProvider.getTranslationForLanguage(request, response, "de");

		assertNotModifiedResponse(response);
		assertThat(resourceProvider.cacheSize(), is(1));
	}

	private void assertOkResponse(MockHttpServletResponse response, String contentType) {
		assertThat(response.getStatus(), is(HttpStatus.OK.value()));
		assertHeaders(response, contentType);
		var responseContentAsByteArray = response.getContentAsByteArray();
		assertThat(response.getHeader(HttpHeaders.CONTENT_LENGTH), is(Integer.toString(responseContentAsByteArray.length)));
		assertThat(responseContentAsByteArray, is(not(nullValue())));
	}

	private void assertNotModifiedResponse(MockHttpServletResponse response) {
		assertThat(response.getStatus(), is(HttpStatus.NOT_MODIFIED.value()));
		assertHeaders(response, null);
		assertThat(response.getContentAsByteArray(), is(new byte[0]));
	}

	private static void assertHeaders(MockHttpServletResponse response, String contentType) {
		assertThat(response.getHeader(HttpHeaders.CONTENT_TYPE), is(contentType));
		assertThat(response.getHeader(HttpHeaders.ETAG), startsWith("\""));
		assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL), startsWith(WebUtil.CACHE_CONTROL_MAX_AGE));
		assertTrue(StringUtils.isEmpty(response.getHeader(HttpHeaders.PRAGMA)));
		assertThat(response.getHeader(HttpHeaders.LAST_MODIFIED), is(not(nullValue())));
	}
}
