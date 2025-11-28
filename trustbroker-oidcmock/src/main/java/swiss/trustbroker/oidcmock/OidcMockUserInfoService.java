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

package swiss.trustbroker.oidcmock;

import java.util.Map;

import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

@Service
public class OidcMockUserInfoService {

	public OidcUserInfo loadUser(String username) {
		return new OidcUserInfo(findByUsername(username));
	}

	public Map<String, Object> findByUsername(String username) {
		return createUser(username);
	}

	private static Map<String, Object> createUser(String username) {
		var cleanedUsername = username.replaceAll("[^a-zA-Z0-9]", ".");
		return OidcUserInfo.builder()
						   .subject(username)
						   .givenName(cleanedUsername + "GivenName")
						   .familyName(cleanedUsername + "FamilyName")
						   .email(cleanedUsername + "@trustbroker.swiss")
						   .build()
						   .getClaims();
	}
}
