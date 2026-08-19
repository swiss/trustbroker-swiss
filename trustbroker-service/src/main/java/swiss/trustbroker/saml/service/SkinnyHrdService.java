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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.velocity.app.VelocityEngine;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.saml.util.VelocityUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.saml.dto.UiObject;
import swiss.trustbroker.util.ApiSupport;

@Slf4j
@AllArgsConstructor
@Service
public class SkinnyHrdService {

	static final String DEFAULT_CPURN = "MissingCPUrn";

	static final String DEFAULT_COLOR = "#FF0000";

	private final TrustBrokerProperties trustBrokerProperties;

	private final VelocityEngine velocityEngine;

	private final ApiSupport apiSupport;

	public void renderSkinnyHrdPage(List<UiObject> uiObjects, String authnRequestId, HttpServletResponse response) {
		Map<String, Object> params = new HashMap<>();
		params.put(VelocityUtil.VELOCITY_PARAM_VERSION, trustBrokerProperties.getVersionInfo());
		List<UiObject> tiles = uiObjects.stream().map(ui -> convertUiObject(ui, authnRequestId)).toList();
		params.put(VelocityUtil.VELOCITY_PARAM_TILES, tiles);
		VelocityUtil.renderTemplate(velocityEngine, response, VelocityUtil.VELOCITY_TEMPLATE_SKINNY_HRD, params);
	}

	private UiObject convertUiObject(UiObject uiObject, String authnRequestId) {
		var result = new UiObject();
		// ID is most important
		var cpId = uiObject.getUrn() != null ? uiObject.getUrn() : DEFAULT_CPURN;
		var urn = apiSupport.getHrdCpApi(cpId, authnRequestId);
		result.setUrn(urn);
		// visibility attributes
		if (uiObject.getDescription() == null) {
			log.warn("Missing description in uiObject={}", uiObject);
		}
		var description = uiObject.getDescription() != null ? uiObject.getDescription() : "";
		result.setDescription(description);
		var shortcut = uiObject.getShortcut();
		if (shortcut == null) {
			shortcut = description.length() <= 2 ? description : description.substring(0, 2);
		}
		result.setShortcut(shortcut);
		var color = uiObject.getColor() != null ?  uiObject.getColor() : DEFAULT_COLOR;
		result.setColor(color);
		if (uiObject.getName() == null) {
			log.warn("Missing name in uiObject={}", uiObject);
		}
		var cpName = uiObject.getName() != null ? uiObject.getName().replaceAll(" .*", "") : "";
		result.setName(cpName);
		return result;
	}

}
