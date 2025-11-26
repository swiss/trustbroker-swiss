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

import java.util.Arrays;
import java.util.List;

import jakarta.xml.bind.annotation.XmlEnumValue;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * OIDC authorization grant types.
 * <br/>
 * The enum values are lower case in the XSD as OIDC uses them in lower case too.
 * <br/>
 * The deprecated type <code>password</code> is not accepted.
 * <br/>
 * Potentially breaking changes:
 * <ul>
 *     <li>Since 1.7.0 only the values defined in this enum are accepted. However, other values - except for
 *     <code>password</code> - were not functional before (including <code>implicit</code>).</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8628">RFC 8628</a>
 * @see <a href="https://datatracker.ietf.org/doc/rfc8693/">RFC 8693</a>
 * @since 1.7.0
 */
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Getter
public enum AuthorizationGrantType {

	@XmlEnumValue("authorization_code")
	AUTHORIZATION_CODE(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE, true),

	@XmlEnumValue("refresh_token")
	REFRESH_TOKEN(org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN, true),

	@XmlEnumValue("client_credentials")
	CLIENT_CREDENTIALS(org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS, false),

	@XmlEnumValue("jwt_bearer")
	JWT_BEARER(org.springframework.security.oauth2.core.AuthorizationGrantType.JWT_BEARER, false),

	@XmlEnumValue("device_code")
	DEVICE_CODE(org.springframework.security.oauth2.core.AuthorizationGrantType.DEVICE_CODE, false),

	@XmlEnumValue("token_exchange")
	TOKEN_EXCHANGE(org.springframework.security.oauth2.core.AuthorizationGrantType.TOKEN_EXCHANGE, false);

	private static final List<AuthorizationGrantType> DEFAULT_VALUES =
			Arrays.stream(values()).filter(AuthorizationGrantType::isDefaultValue).toList();

	private final org.springframework.security.oauth2.core.AuthorizationGrantType type;

	private boolean defaultValue;

	public String getName() {
		return type.getValue();
	}

	public static List<AuthorizationGrantType> defaultValues() {
		return DEFAULT_VALUES;
	}

}
