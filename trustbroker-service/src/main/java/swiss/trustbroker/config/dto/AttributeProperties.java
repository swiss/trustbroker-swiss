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

package swiss.trustbroker.config.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;

/**
 * Configuration of individual attributes.
 /**
 * Configuration of attributes.
 *
 * @see swiss.trustbroker.federation.xmlconfig.Definition
 * @see swiss.trustbroker.api.sessioncache.service.AttributeInitializer
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttributeProperties implements AttributeName {

	/**
	 * 	Short name used in auditing and for IDM attribute addressing.
	 */
	private String name;

	/**
	 * 	Known external attributes we just document here - used when we cannot use namespaceUri due to semantics.
	 */
	private String altName;

	/**
	 * The long name is used in the generated SAML assertion towards the RP.
	 */
	private String namespaceUri;

	/**
	 * The claim names used when emitting an attribute to an OIDC client.
	 */
	private List<String> oidcNameList;

	/**
	 * The claim mappers used for mapping the values.
	 */
	private String mappers;

}
