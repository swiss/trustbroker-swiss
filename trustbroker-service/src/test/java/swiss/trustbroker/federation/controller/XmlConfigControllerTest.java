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

import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import swiss.trustbroker.federation.dto.ConfigStatus;
import swiss.trustbroker.federation.dto.ConfigStatusData;
import swiss.trustbroker.federation.service.SchemaDefinitionService;
import swiss.trustbroker.federation.service.XmlConfigStatusService;
import swiss.trustbroker.util.ApiSupport;

@ExtendWith(SpringExtension.class)
@WebMvcTest
@ContextConfiguration(classes = {
		XmlConfigController.class
})
@AutoConfigureMockMvc
class XmlConfigControllerTest {

	@MockitoBean
	private SchemaDefinitionService schemaDefinitionService;

	@MockitoBean
	private XmlConfigStatusService configStatusService;

	@Autowired
	private WebApplicationContext webApplicationContext;

	private MockMvc mockMvc;

	@BeforeEach
	void setup() {
		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext).build();
	}

	@Test
	void schemasApi() throws Exception {
		var xsd = "RelyingPartySetup.xsd";
		var data = """
				<?xml version="1.0" encoding="UTF-8"?>
				<test></test>
				""";
		doReturn(data.getBytes(StandardCharsets.UTF_8)).when(schemaDefinitionService).getSchema(xsd);

		this.mockMvc.perform(get(ApiSupport.CONFIG_SCHEMAS_API + '/' + xsd))
					.andExpect(status().isOk())
					.andExpect(content().xml(data));

	}

	@Test
	void statusApi() throws Exception {
		var status = ConfigStatusData.builder().status(ConfigStatus.WARN).build();
		doReturn(status).when(configStatusService).getConfigStatus();
		var statusJson = """
					{status:"WARN"}
				""";

		this.mockMvc.perform(get(ApiSupport.CONFIG_STATUS_API))
					.andExpect(status().isOk())
					.andExpect(content().json(statusJson));

	}
}
