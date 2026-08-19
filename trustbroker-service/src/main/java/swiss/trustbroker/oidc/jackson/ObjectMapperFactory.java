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

package swiss.trustbroker.oidc.jackson;

import org.springframework.security.jackson.SecurityJacksonModules;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

// Do not make this a component (will affect whole framework)
public class ObjectMapperFactory {

	private ObjectMapperFactory() {
	}

	// Internal use only when we read object trees from token database
	public static JsonMapper springSecObjectMapper() {
		var validatorBuilder = BasicPolymorphicTypeValidator.builder()
		                                                    .allowIfSubType("java.lang")
		                                                    .allowIfSubType("java.util");
		var classLoader = ObjectMapperFactory.class.getClassLoader();
		var securityModules = SecurityJacksonModules.getModules(classLoader, validatorBuilder);
		var typeValidator = validatorBuilder.build();
		return JsonMapper.builder()
		                 .polymorphicTypeValidator(typeValidator)
		                 .addModules(securityModules)
		                 .build();
	}

}
