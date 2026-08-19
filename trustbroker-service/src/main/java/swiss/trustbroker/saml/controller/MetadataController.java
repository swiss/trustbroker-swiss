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

package swiss.trustbroker.saml.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import swiss.trustbroker.federation.service.FederationMetadataService;
import swiss.trustbroker.util.ApiSupport;

/**
 * This is the controller for metadata related interaction.
 */
@RestController
@AllArgsConstructor
@ConditionalOnExpression("${trustbroker.config.saml.enabled} or ${trustbroker.config.wstrust.enabled}")
public class MetadataController {

	private final FederationMetadataService federationMetadataService;

	// Federation metadata endpoint XML
	@GetMapping(path = {
			ApiSupport.SAML_METADATA_URL,
			ApiSupport.METADATA_URL,
			ApiSupport.XTB_LOWER_CASE_ALTERNATE_METADATA_ENDPOINT,
			ApiSupport.XTB_ALTERNATE_METADATA_ENDPOINT // camel-case deprecated but documented in old MS docs
	}, produces = MediaType.APPLICATION_XML_VALUE)
	public String handleFederationMetadata(HttpServletRequest request, HttpServletResponse response) {
		return federationMetadataService.getFederationMetadata(true, true);
	}

	// RP side only
	@GetMapping(path = { ApiSupport.SAML_METADATA_URL + "/sp" }, produces = MediaType.APPLICATION_XML_VALUE)
	public String handleSpFederationMetadata(HttpServletRequest request, HttpServletResponse response) {
		return federationMetadataService.getFederationMetadata(false, true);
	}

	// CP side only
	@GetMapping(path = { ApiSupport.SAML_METADATA_URL + "/idp" }, produces = MediaType.APPLICATION_XML_VALUE)
	public String handleIdpFederationMetadata(HttpServletRequest request, HttpServletResponse response) {
		return federationMetadataService.getFederationMetadata(true, false);
	}
}
