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

import java.io.StringWriter;

import swiss.trustbroker.federation.xmlconfig.Definition;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

/**
 * Because jackson cannot properly deal with complex map keys, custom serialization support on maps are necessary.
 * https://github.com/FasterXML/jackson-docs/wiki/JacksonHowToCustomSerializers
 */
public class DefinitionSerializer extends ValueSerializer<Definition> {

	private ObjectMapper mapper = new ObjectMapper();

	@Override
	public void serialize(Definition value, JsonGenerator gen, SerializationContext serializers) {
		var writer = new StringWriter();
		mapper.writeValue(writer, value);
		gen.writeName(writer.toString());
	}

}
