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

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.audit.dto.EventType;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.audit.service.OutboundAuditMapper;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.oidc.session.TomcatSession;

@Service
@AllArgsConstructor
public class OidcAuditService {

	private final AuditService auditService;

	public void auditTokenClaims(String clientId, JwtEncodingContext context, String kid, String ssoSessionId,
	                             String conversationId, TrustBrokerProperties properties, TomcatSession session,
	                             HttpServletRequest request) {
		// OIDC claims in data section
		var auditDtoBuilder = new OutboundAuditMapper(properties);
		context.getClaims()
		       .claims(attrMap ->
					   auditDtoBuilder.mapFromClaims(attrMap, AuditDto.AttributeSource.OIDC_RESPONSE)
			   );

		// add referer and other helpful stuff
		auditDtoBuilder.mapFrom(request);

		// kid header so we can track key rotation
		var auditDto = auditDtoBuilder.build();
		if (kid != null) {
			auditDtoBuilder.mapFromClaims(Map.of(OidcUtil.OIDC_HEADER_KEYID, kid), AuditDto.AttributeSource.OIDC_RESPONSE);
		}

		// overwrite referer with the original caller, so we can better correlate the application
		auditDto.setReferrer(getCurrentReferrer(session));

		// correlation with SAML side sending ssoSessionId usually
		auditDto.setSsoSessionId(ssoSessionId);

		// correlated with initial OIDC session
		auditDto.setConversationId(conversationId);

		// correlation by message marker
		auditDto.setMessageId(getCurrentMessageId(request));

		// token type influences log level as access_token and id_token are mostly the same
		var tokenType = context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN) ?
				EventType.OIDC_TOKEN : EventType.OIDC_IDTOKEN;
		auditDto.setEventType(tokenType);
		auditDto.setSide(DestinationType.RP.getLabel());

		auditDto.setOidcClientId(clientId);

		if (context.getAuthorizationGrantType() != null) {
			auditDto.setGrantType(context.getAuthorizationGrantType().getValue());
		}

		auditService.logOutboundFlow(auditDto);
	}

	private static String getCurrentReferrer(TomcatSession session) {
		if (session != null) {
			return session.getStateData().getRpReferer();
		}
		return null;
	}

	private static String getCurrentMessageId(HttpServletRequest request) {
		if (request != null) {
			// at the moment we log this, the code is consumed and invalidated
			return StringUtil.clean(request.getParameter(OidcUtil.OIDC_CODE));
		}
		return null;
	}

	public void auditTokenRequest(HttpServletRequest request, TrustBrokerProperties properties) {
		var auditDtoBuilder = new OutboundAuditMapper(properties);

		Map<String, String[]> parameterMap = request.getParameterMap();

		auditDtoBuilder.mapFrom(request);

		auditDtoBuilder.mapFromTokenRequestParams(parameterMap);

		var auditDto = auditDtoBuilder.build();

		auditDto.setEventType(EventType.OIDC_TOKEN_REQUEST);

		auditService.logOutboundFlow(auditDto);
	}
}
