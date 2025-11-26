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

import java.util.function.Consumer;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.opensaml.core.xml.XMLObject;
import org.slf4j.Logger;
import swiss.trustbroker.audit.dto.EventType;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;

/**
 * Base class of loggers that perrform the actual logging. Separate class to allow mocking in tests.
 * <br/>
 * Audit entries emitted as follows:
 * <ul>
 * <li>INFO: RP.AuthnRequest, RP.Response, RP.LogoutRequest</li>
 * <li>DEBUG: CP.AuthnRequest, CP.Response</li>
 * <li>TRACE: AttributeValue marked with FQ name</li>
 * <li>If AuditLoggerDetails=TRACE the full SAML message is attached as a detail field (large).</li>
 * </ul>
 */
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class BaseAuditLogger implements AuditLogger {

	protected static final String DETAILS_LOGGER_POSTFIX = "Details";

	@Override
	public void log(EventType eventType, boolean inbound, String message) {
		logLevel(getLogger(), eventType, inbound).accept(message);
	}

	/**
	 * @return logger to use
	 */
	protected abstract Logger getLogger();

	/**
	 * @return logger to use for details
	 */
	protected abstract Logger getDetailLogger();

	private static Consumer<String> logLevel(Logger log, EventType eventType, boolean inbound) {
		return switch (eventType) {
			// in: conversation start, RP authnrequest, CP unknown / out: conversation continue, CP selected
			case AUTHN_REQUEST -> inbound ? log::info : log::debug;
			// in: conversation continue, CP responded / out: conversation done, response to RP
			case RESPONSE -> inbound ? log::debug : log::info;
			// in: conversation continue, CP responded / out: conversation done, response to RP
			case LOGOUT_REQUEST -> log::info;
			case OIDC_LOGOUT -> log::info;
			// in: logout initiated by TB, RP responded / out: logout initiated by RP, response to RP
			case LOGOUT_RESPONSE -> inbound ? log::debug : log::info;
			case RST_REQUEST -> log::debug;
			case RST_RESPONSE -> log::info;
			case OIDC_TOKEN -> log::info; // access_token is not opaque so we log that primarily
			case OIDC_IDTOKEN -> log::debug; // id_token has same content currently so DEBUG
			// in: artifact resolve
			case ARTIFACT_RESOLVE -> log::debug;
			// out: artifact response
			case ARTIFACT_RESPONSE -> log::info;
			default -> log::warn;
		};
	}

	@Override
	public String getAuditDetail(final XMLObject xmlObject) {
		if (xmlObject != null && isDetailAuditingEnabled()) {
			return OpenSamlUtil.samlObjectToString(xmlObject, true, false);
		}
		return null;
	}

	protected boolean isDetailAuditingEnabled() {
		return getDetailLogger().isTraceEnabled();
	}

}
