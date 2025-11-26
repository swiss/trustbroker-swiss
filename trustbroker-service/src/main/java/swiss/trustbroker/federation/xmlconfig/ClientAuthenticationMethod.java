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
import org.apache.commons.lang3.EnumUtils;

/**
 * OIDC client authentication methods.
 * <br/>
 * The enum values are lower case in the XSD as OIDC uses them in lower case too.
 * <br/>
 * Potentially breaking changes:
 * <ul>
 *     <li>Since 1.7.0 only the values defined in this enum are accepted. However, other values were not functional before.</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">OIDC ClientAuthentication</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8705">RFC 8705</a>
 */
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Getter
public enum ClientAuthenticationMethod {

	@XmlEnumValue("none")
	NONE(org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE, true),

	@XmlEnumValue("client_secret_basic")
	CLIENT_SECRET_BASIC(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC, true),

	@XmlEnumValue("client_secret_post")
	CLIENT_SECRET_POST(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_POST, true),

	@XmlEnumValue("client_secret_jwt")
	CLIENT_SECRET_JWT(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_JWT, false),

	@XmlEnumValue("private_key_jwt")
	PRIVATE_KEY_JWT(org.springframework.security.oauth2.core.ClientAuthenticationMethod.PRIVATE_KEY_JWT, false),

	@XmlEnumValue("tls_client_auth")
	TLS_CLIENT_AUTH(org.springframework.security.oauth2.core.ClientAuthenticationMethod.TLS_CLIENT_AUTH, false),

	@XmlEnumValue("self_signed_tls_client_auth")
	SELF_SIGNED_TLS_CLIENT_AUTH(
			org.springframework.security.oauth2.core.ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH, false);

	private static final List<ClientAuthenticationMethod> DEFAULT_VALUES =
			Arrays.stream(values()).filter(ClientAuthenticationMethod::isDefaultValue).toList();

	private final org.springframework.security.oauth2.core.ClientAuthenticationMethod method;

	private boolean defaultValue;

	public String getName() {
		return method.getValue();
	}

	public static List<ClientAuthenticationMethod> defaultValues() {
		return DEFAULT_VALUES;
	}

	public static ClientAuthenticationMethod valueOfIgnoreCase(Object value) {
		if (value == null) {
			return null;
		}
		if (value instanceof ClientAuthenticationMethod enumValue) {
			return enumValue;
		}
		if (value instanceof org.springframework.security.oauth2.core.ClientAuthenticationMethod method) {
			return EnumUtils.getEnumIgnoreCase(ClientAuthenticationMethod.class, method.getValue());
		}
		return EnumUtils.getEnumIgnoreCase(ClientAuthenticationMethod.class, value.toString());
	}

}
