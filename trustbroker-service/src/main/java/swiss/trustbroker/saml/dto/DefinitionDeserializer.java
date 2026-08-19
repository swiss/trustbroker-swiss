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

package swiss.trustbroker.saml.dto;

import swiss.trustbroker.federation.xmlconfig.Definition;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.KeyDeserializer;
import tools.jackson.databind.ObjectMapper;

/**
 * Because jackson cannot properly deal with complex map keys, custom deserialization support on maps are necessary.
 * https://github.com/FasterXML/jackson-docs/wiki/JacksonHowToCustomSerializers
 */
public class DefinitionDeserializer extends KeyDeserializer {

	private ObjectMapper mapper = new ObjectMapper();

	@Override
	public Definition deserializeKey(String key, DeserializationContext ctxt) {
		return mapper.readValue(key, Definition.class);
	}

}
