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

package swiss.trustbroker.saml.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;

import java.util.List;

import org.apache.velocity.app.VelocityEngine;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.saml.dto.UiObject;
import swiss.trustbroker.saml.test.util.ServiceSamlTestUtil;
import swiss.trustbroker.util.ApiSupport;

@SpringBootTest(classes = { SamlServiceTestConfiguration.class, SkinnyHrdService.class, ApiSupport.class })
class SkinnyHrdServiceTest extends ServiceSamlTestUtil {

	private static final String URN = "urn1";

	private static final String TILE_TITLE = "tileTitle1";

	private static final String TILE_TITLE_2 = "second title 2";

	private static final String TILE_TITLE_2_SHORT = "se";

	private static final String COLOR = "#112233";

	private static final String SHORTCUT = "shortcut1";

	private static final String NAME = "name1";

	private static final String NAME_2 = "another one";

	private static final String NAME_2_SHORT = "another";

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@Autowired
	private VelocityEngine velocityEngine;

	@Autowired
	private ApiSupport apiSupport;

	@Autowired SkinnyHrdService skinnyHrdService;

	@Test
	void renderSkinnyHrdPage() throws Exception {
		var uiObjects = givenUiObjects();
		var requestId = "authnrequest123";
		var response = new MockHttpServletResponse();

		skinnyHrdService.renderSkinnyHrdPage(uiObjects, requestId, response);

		// entry 1
		var body = response.getContentAsString();
				// entry 1:
		assertThat(body, containsString(apiSupport.getHrdCpApi(URN, requestId)));
		assertThat(body, containsString(TILE_TITLE));
		assertThat(body, containsString(SHORTCUT));
		assertThat(body, containsString(COLOR));
		assertThat(body, containsString(NAME));
		// entry 2:
		assertThat(body, containsString(apiSupport.getHrdCpApi(SkinnyHrdService.DEFAULT_CPURN, requestId)));
		assertThat(body, containsString(TILE_TITLE_2));
		assertThat(body, containsString(TILE_TITLE_2_SHORT));
		assertThat(body, containsString(SkinnyHrdService.DEFAULT_COLOR));
		assertThat(body, containsString(NAME_2_SHORT));
	}

	private static List<UiObject> givenUiObjects() {
		return List.of(
				// complete:
				UiObject.builder().urn(URN).description(TILE_TITLE).shortcut(SHORTCUT).name(NAME).color(COLOR).build(),
				// minimal, with truncations:
				UiObject.builder().description(TILE_TITLE_2).name(NAME_2).build()
		);
	}

}
