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

import java.util.List;

import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.saml.dto.UiObject;
import swiss.trustbroker.util.ApiSupport;

@Slf4j
public class SkinnyHrd {

	public static final String SKINNY_HRD_HTML = "/skinnyHRD.html";

	static final String DEFAULT_CPURN = "MissingCPUrn";

	static final String DEFAULT_SHORT_COLOR = "FF0000";

	static final char ENTRY_SEPARATOR = ';';

	static final char ATTRIBUTE_SEPARATOR = ',';

	private SkinnyHrd() {
	}

	// GET URL contains ; separated records: urn,title,shortcut,color
	public static String buildSkinnyHrdPage(List<UiObject> uiObjects, String skinnyHtml) {
		var pageContent = new StringBuilder();

		for (var uiObject : uiObjects) {
			if (!pageContent.isEmpty()) {
				pageContent.append(ENTRY_SEPARATOR);
			}
			// ID is most important
			var urn = ApiSupport.encodeUrlParameter(uiObject.getUrn() != null ? uiObject.getUrn() : DEFAULT_CPURN);
			pageContent.append(urn).append(ATTRIBUTE_SEPARATOR);
			// visibility attributes
			if (uiObject.getDescription() == null) {
				log.warn("Missing description in uiObject={}", uiObject);
			}
			var longTitle = uiObject.getDescription() != null ? uiObject.getDescription().replace(" ", "_") : "";
			pageContent.append(longTitle).append(ATTRIBUTE_SEPARATOR);
			var shortTitle = uiObject.getShortcut() != null ? uiObject.getShortcut() : longTitle.substring(0, 2);
			pageContent.append(shortTitle);
			// backward compat to initial version
			if (!skinnyHtml.equals(SKINNY_HRD_HTML)) {
				setPageContent(pageContent, uiObject);
			}
		}
		return pageContent.toString();
	}

	private static void setPageContent(StringBuilder pageContent, UiObject uiObject) {
		pageContent.append(ATTRIBUTE_SEPARATOR);
		var shortColor = uiObject.getColor();
		if (shortColor == null || !shortColor.startsWith("#")) {
			shortColor = DEFAULT_SHORT_COLOR;
		}
		else {
			shortColor = shortColor.replace("#", ""); // skinnyUI re-appends it, only HEX color codes please
		}
		pageContent.append(shortColor).append(ATTRIBUTE_SEPARATOR);
		if (uiObject.getName() == null) {
			log.warn("Missing name in uiObject={}", uiObject);
		}
		var cpName = uiObject.getName() != null ? uiObject.getName().replaceAll(" .*", "") : "";
		pageContent.append(cpName).append(ATTRIBUTE_SEPARATOR);
		var cpImage = uiObject.getImage() != null ? uiObject.getImage() : "";
		pageContent.append(cpImage);
	}

}
