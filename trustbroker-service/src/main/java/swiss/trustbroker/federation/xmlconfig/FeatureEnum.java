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

package swiss.trustbroker.federation.xmlconfig;

import jakarta.xml.bind.annotation.XmlEnumValue;

/**
 * Configuration enabling toggle.
 * <br/>
 * The enum values are lower case in the XSD to allow using the usual boolean true/false values.
 * Potentially breaking changes:
 * <ul>
 *     <li>Since 1.7.0 the values are accepted just in lower case (with 1.6.0 in any case, before only lower case).</li>
 * </ul>
 */
public enum FeatureEnum {
	/**
	 * Enabled
	 */
	@XmlEnumValue("true")
	TRUE,

	/**
	 * Disabled. XTB will load and validate the configuration, but not use it.
	 */
	@XmlEnumValue("false")
	FALSE,

	/**
	 * Configuration invalid or not yet ready for enabling. XTB will not load the config.
	 */
	@XmlEnumValue("invalid")
	INVALID
}
