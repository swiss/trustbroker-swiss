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

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.google.common.base.Functions;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.oauth2.core.oidc.OidcScopes;

/**
 * OIDC scopes.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims">OIDC ScopeClaims</a>
 * @since 1.7.0
 */
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Getter
public class Scope {

	public static final Scope OPENID = new Scope(OidcScopes.OPENID, true);

	public static final Scope PROFILE = new Scope(OidcScopes.PROFILE, true);

	public static final Scope EMAIL = new Scope(OidcScopes.EMAIL, true);

	public static final Scope ADDRESS = new Scope(OidcScopes.ADDRESS, true);

	public static final Scope PHONE = new Scope(OidcScopes.PHONE, true);

	private static final List<Scope> DEFAULT_VALUES = List.of(OPENID, PROFILE, EMAIL, ADDRESS, PHONE);

	private static final Map<String, Scope> SCOPES = DEFAULT_VALUES.stream()
			.collect(Collectors.toMap(Scope::getName, Functions.identity()));

	private static final List<String> DEFAULT_NAMES = DEFAULT_VALUES.stream().map(Scope::getName).toList();

	private final String name;

	private boolean defaultValue;

	public static List<Scope> defaultValues() {
		return DEFAULT_VALUES;
	}

	public static List<String> defaultNames() {
		return DEFAULT_NAMES;
	}

	public static Scope of(String name) {
		var result = SCOPES.get(name);
		if (result == null) {
			result = new Scope(name, false);
		}
		return result;
	}

}
