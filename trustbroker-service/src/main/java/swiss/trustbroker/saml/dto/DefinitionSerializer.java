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

package swiss.trustbroker.saml.dto;

import java.io.IOException;
import java.io.StringWriter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import swiss.trustbroker.federation.xmlconfig.Definition;

/**
 * Because jackson cannot properly deal with complex map keys, custom serialization support on maps are necessary.
 * https://github.com/FasterXML/jackson-docs/wiki/JacksonHowToCustomSerializers
 */
public class DefinitionSerializer extends JsonSerializer<Definition> {

	private ObjectMapper mapper = new ObjectMapper();

	@Override
	public void serialize(Definition value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
		StringWriter writer = new StringWriter();
		mapper.writeValue(writer, value);
		gen.writeFieldName(writer.toString());
	}

}
