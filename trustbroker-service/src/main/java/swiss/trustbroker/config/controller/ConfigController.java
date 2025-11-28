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

package swiss.trustbroker.config.controller;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.VersionInfo;
import swiss.trustbroker.gui.GuiSupport;
import swiss.trustbroker.homerealmdiscovery.dto.GuiConfig;
import swiss.trustbroker.util.ApiSupport;

/**
 * Controller for the version API.
 */
@Controller
@AllArgsConstructor
public class ConfigController {

	private final TrustBrokerProperties trustBrokerProperties;

	@GetMapping(path = ApiSupport.VERSION_API)
	@ResponseBody
	public VersionInfo getVersion() {
		return new VersionInfo(trustBrokerProperties.getVersionInfo());
	}

	@GetMapping(value = ApiSupport.CONFIG_FRONTEND_API)
	@ResponseBody
	public GuiConfig getGuiConfig() {
		return GuiSupport.buildConfig(trustBrokerProperties.getGui());
	}
}
