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

package swiss.trustbroker.audit.service;

import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.audit.dto.EventType;
import swiss.trustbroker.metrics.service.MetricsService;

@Service
@AllArgsConstructor
public class AuditService {

	private static final Map<EventType, String> PREFIXES = Map.of(
			EventType.AUTHN_REQUEST, "AuthnRequest: ",
			EventType.RESPONSE, "AuthnResponse: ",
			EventType.LOGOUT_REQUEST, "LogoutRequest: ",
			EventType.LOGOUT_RESPONSE, "LogoutResponse: ",
			EventType.RST_REQUEST, "RstRequest: ",
			EventType.RST_RESPONSE, "RstResponse: "
	);

	private static final String MAPPED_RESPONSE_TYPE = "response";

	private static final String MAPPED_LOGOUT_TYPE = "logout";

	private static final Map<EventType, String> EVENTS = Map.of(
			EventType.AUTHN_REQUEST, "authnrequest",
			EventType.RESPONSE, MAPPED_RESPONSE_TYPE,
			EventType.LOGOUT_REQUEST, MAPPED_LOGOUT_TYPE,
			EventType.LOGOUT_RESPONSE, MAPPED_RESPONSE_TYPE,
			EventType.RST_REQUEST, "rst",
			EventType.RST_RESPONSE, MAPPED_RESPONSE_TYPE,
			EventType.OIDC_TOKEN, "token", // OIDC access_token response
			EventType.OIDC_IDTOKEN, "id_token",
			EventType.OIDC_LOGOUT, MAPPED_LOGOUT_TYPE
	);

	private final List<AuditLogger> loggers;

	public final MetricsService metricsService;

	public void logInboundFlow(AuditDto auditDto) {
		for (var logger : loggers) {
			var incomingMessage = buildRoutingMessage(logger, auditDto);
			logger.log(auditDto.getEventType(), true, incomingMessage.build());
			String[] labels = getMetricsLabels(auditDto);
			metricsService.increment(auditDto.getEventType(), EVENTS.get(auditDto.getEventType()), labels);
		}
	}

	private static String[] getMetricsLabels(AuditDto auditDto) {
		var clientId = auditDto.getOidcClientId() != null ? auditDto.getOidcClientId() : auditDto.getApplicationName();
		return new String[] { MetricsService.CP_ISSUER_LABEL, auditDto.getCpIssuer(),
				MetricsService.RP_ISSUER_LABEL, auditDto.getRpIssuer(),
				MetricsService.CLIENT_ID_LABEL, clientId,
				MetricsService.DESTINATION_LABEL, auditDto.getDestination(),
				MetricsService.TYPE_LABEL, EVENTS.get(auditDto.getEventType()),
				MetricsService.STATUS_LABEL, auditDto.getStatus() };
	}

	public void logOutboundFlow(AuditDto auditDto) {
		for (var logger : loggers) {
			var incomingMessage = buildRoutingMessage(logger, auditDto);
			logger.log(auditDto.getEventType(), false, incomingMessage.build());
			String[] labels = getMetricsLabels(auditDto);
			metricsService.increment(auditDto.getEventType(), EVENTS.get(auditDto.getEventType()), labels);

		}
	}

	private static AuditLogBuilder buildRoutingMessage(AuditLogger logger, AuditDto auditDto) {
		String prefix = PREFIXES.get(auditDto.getEventType());
		var logBuilder = logger.createAuditLogBuilder(prefix);

		logBuilder.append(AuditDto.EVENT_NAME, EVENTS.get(auditDto.getEventType()));
		logBuilder.appendDtoFields(auditDto);

		var auditDetail = logger.getAuditDetail(auditDto.getSamlMessage());
		if (auditDetail != null) {
			logBuilder.append(AuditDto.DETAIL_NAME, auditDetail);
		}

		return logBuilder;
	}

}
