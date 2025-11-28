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

package swiss.trustbroker.federation.controller;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import swiss.trustbroker.federation.dto.ConfigStatusData;
import swiss.trustbroker.federation.service.SchemaDefinitionService;
import swiss.trustbroker.federation.service.XmlConfigStatusService;
import swiss.trustbroker.util.ApiSupport;

/**
 * Controller for the config API.
 */
@Controller
@Slf4j
@AllArgsConstructor
public class XmlConfigController {

	private final SchemaDefinitionService schemaDefinitionService;

	private final XmlConfigStatusService configStatusService;

	@GetMapping(path = ApiSupport.CONFIG_SCHEMAS_API + "/{schema}")
	@ResponseBody
	public void getSchema(@PathVariable(name = "schema", required = true) String schema, HttpServletResponse response)
			throws IOException {
		var data = schemaDefinitionService.getSchema(schema);
		response.setContentType(MediaType.APPLICATION_XML_VALUE);
		response.getOutputStream().write(data);
	}

	@GetMapping(path = ApiSupport.CONFIG_STATUS_API)
	@ResponseBody
	public ConfigStatusData getConfigStatus() {
		return configStatusService.getConfigStatus();
	}
}
