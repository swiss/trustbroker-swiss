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

package swiss.trustbroker.oidc;

import java.util.Collections;
import java.util.List;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class FirstJwkSource implements JWKSource<SecurityContext> {

	private final JWKSource<SecurityContext> jwkSource;

	@Override
	public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
		List<JWK> jwks = this.jwkSource.get(jwkSelector, securityContext);
		if (jwks == null || jwks.isEmpty()) {
			return Collections.emptyList();
		}
		return Collections.singletonList(jwks.get(0));
	}
}
