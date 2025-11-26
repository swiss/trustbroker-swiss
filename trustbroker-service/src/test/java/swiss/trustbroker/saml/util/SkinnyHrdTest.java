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

package swiss.trustbroker.saml.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.List;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.saml.dto.UiObject;
import swiss.trustbroker.util.ApiSupport;

class SkinnyHrdTest {

	private static final String URN = "urn1";

	private static final String TILE_TITLE = "tileTitle1";

	private static final String TILE_TITLE_2 = "second title 2";

	private static final String TILE_TITLE_2_ENCODED = "second_title_2";

	private static final String TILE_TITLE_2_SHORT = "se";

	private static final String COLOR_ENCODED = "112233";

	private static final String COLOR = '#' + COLOR_ENCODED;

	private static final String SHORTCUT = "shortcut1";

	private static final String NAME = "name1";

	private static final String NAME_2 = "another one";

	private static final String NAME_2_SHORT = "another";

	private static final String IMAGE = "image1";

	@Test
	void buildSkinnyHrdPage() {
		var uiObjects = givenUiObjects();

		var result = SkinnyHrd.buildSkinnyHrdPage(uiObjects, "skinnyTest.html");

		// entry 1
		assertThat(result, is(
				// entry 1:
				ApiSupport.encodeUrlParameter(URN) + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						TILE_TITLE + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						SHORTCUT + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						COLOR_ENCODED + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						NAME + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						IMAGE + SkinnyHrd.ENTRY_SEPARATOR +
				// entry 2:
				ApiSupport.encodeUrlParameter(SkinnyHrd.DEFAULT_CPURN) + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						TILE_TITLE_2_ENCODED + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						TILE_TITLE_2_SHORT + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						SkinnyHrd.DEFAULT_SHORT_COLOR + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						NAME_2_SHORT + SkinnyHrd.ATTRIBUTE_SEPARATOR // + empty image
		));
	}

	@Test
	void buildSkinnyHrdCompat() {
		var uiObjects = givenUiObjects();

		var result = SkinnyHrd.buildSkinnyHrdPage(uiObjects, SkinnyHrd.SKINNY_HRD_HTML);

		// entry 1
		assertThat(result, is(
				// entry 1:
				ApiSupport.encodeUrlParameter(URN) + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						TILE_TITLE + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						SHORTCUT + SkinnyHrd.ENTRY_SEPARATOR +
						// entry 2:
						ApiSupport.encodeUrlParameter(SkinnyHrd.DEFAULT_CPURN) + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						TILE_TITLE_2_ENCODED + SkinnyHrd.ATTRIBUTE_SEPARATOR +
						TILE_TITLE_2_SHORT
		));
	}

	private static List<UiObject> givenUiObjects() {
		return List.of(
				// complete:
				UiObject.builder().urn(URN).description(TILE_TITLE).shortcut(SHORTCUT).name(NAME).image(IMAGE).color(COLOR).build(),
				// minimal, with truncations:
				UiObject.builder().description(TILE_TITLE_2).name(NAME_2).build()
		);
	}

}
