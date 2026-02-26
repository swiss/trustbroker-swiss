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

import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.OidcClient;

@AllArgsConstructor
public class TokenExchangeResponseCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private final  Map<String, Object> attributes;

	private final OidcClient oidcClient;

	private final TrustBrokerProperties properties;

	@Override
	public void customize(JwtEncodingContext context) {
		// Normalize time claims
		Instant now = Instant.now();
		context.getClaims().claim(OidcUtil.OIDC_ISSUED_AT, now.getEpochSecond());
		context.getClaims().claim(OidcUtil.OIDC_NOT_BEFORE, now);

		var tokenTimeToLiveMin = oidcClient.getOidcSecurityPolicies().getTokenTimeToLiveMin();
		var tokenTimeToLive = tokenTimeToLiveMin != null ? tokenTimeToLiveMin * 60 : properties.getSecurity().getTokenLifetimeSec();
		context.getClaims().claim(OidcUtil.OIDC_EXPIRATION_TIME, now.plusSeconds(tokenTimeToLive).getEpochSecond());

		// Normalize audience
		Object aud = context.getClaims().build().getClaim(OidcUtil.OIDC_AUDIENCE);
		if (aud instanceof Collection<?>) {
			List<String> audience = new ArrayList<>();
			for (Object o : (Collection<?>) aud) {
				audience.add(String.valueOf(o));
			}
			context.getClaims().claim(OidcUtil.OIDC_AUDIENCE, audience);
		}
		else if (aud != null) {
			context.getClaims().claim(OidcUtil.OIDC_AUDIENCE, List.of(String.valueOf(aud)));
		}

		Object iss = context.getClaims().build().getClaim(OidcUtil.OIDC_ISSUER);
		if (iss instanceof URL url) {
			context.getClaims().claim(OidcUtil.OIDC_ISSUER, (url).toString());
		}
		else if (iss != null) {
			context.getClaims().claim(OidcUtil.OIDC_ISSUER, String.valueOf(iss));
		}

		if (attributes != null) {
			addAttributesToContext(context);
		}
	}

	private void addAttributesToContext(JwtEncodingContext context) {
		attributes.forEach((key, value) -> {
			if (value == null) return;
			if (value instanceof Instant instantValue) {
				context.getClaims().claim(key, instantValue.getEpochSecond());
			}
			else if (value instanceof Date dateValue) {
				context.getClaims().claim(key, dateValue.toInstant().getEpochSecond());
			}
			else if (value instanceof String || value instanceof Number || value instanceof Boolean) {
				context.getClaims().claim(key, value);
			}
			else if (value instanceof Collection<?> values) {
				if(values.size() == 1) {
					context.getClaims().claim(key, String.valueOf(values.iterator().next()));
				} else {
					List<String> safe = ((Collection<?>) values).stream()
																.map(String::valueOf)
																.toList();
					context.getClaims().claim(key, safe);
				}
			}
			// "cnf" claim
			else if (value instanceof Map<?, ?> map) {
				context.getClaims().claim(key, map);
			}
		});
	}
}
