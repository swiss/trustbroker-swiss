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

package swiss.trustbroker.oidc.jackson;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import swiss.trustbroker.util.LongMixin;

// Do not make this a component (will affect whole framework)
public class ObjectMapperFactory {

	private ObjectMapperFactory() {
	}

	public static ObjectMapper springSecObjectMapper() {
		var classLoader = ObjectMapperFactory.class.getClassLoader();
		var securityModules = SecurityJackson2Modules.getModules(classLoader);
		var mapper = new ObjectMapper();
		mapper.registerModules(securityModules);
		mapper.registerModule(new AuthorizationPrincipalModule());
		mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
		mapper.registerModules(securityModules);
		// https://github.com/spring-projects/spring-session/issues/2305
		mapper.addMixIn(Long.class, LongMixin.class);
		return mapper;
	}

}
