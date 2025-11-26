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

import java.util.Collections;
import java.util.List;

import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

// We store our SAML2 principal attributes and JWT claims in our StateCacheService so allow otherwise blocked data.
// See JdbcOAuth2AuthorizationService for a possibly working spring-sec default setup.
// See https://cowtowncoder.medium.com/jackson-2-10-safe-default-typing-2d018f0ce2ba for insights.
public class AuthorizationPrincipalModule extends OAuth2AuthorizationServerJackson2Module {

	@Override
	public void setupModule(SetupContext context) {
		// spring-sec defaults
		super.setupModule(context);

		// Add all data we trust to handle as principal data in XTB.
		// We are not mixing in data here, just mark classes with missing @Json annotations to be white listed
		// WARNING: This restricts what can be done in groovy scripts as claim values!!!
		context.setMixInAnnotations(Long.class, ObjectMixin.class); // JWT token epoc time
		context.setMixInAnnotations(List.of().getClass(), ObjectMixin.class); // ListN
		context.setMixInAnnotations(List.of("TEXT").getClass(), ObjectMixin.class); // List12
		context.setMixInAnnotations(Collections.emptyList().getClass(), ObjectMixin.class); // EmptyList
	}

}
