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


import org.opensaml.core.xml.XMLObject;
import swiss.trustbroker.audit.dto.EventType;

/**
 * Interface for audit logging.
 */
public interface AuditLogger {

	/**
	 * Audit message and context data to analyze login traffic and record what's needed for compliance.
	 * @param eventType is SAML AuthnRequest or Response
	 * @param inbound means messages coming in (AuthnRequest from RP or Response from CP)
	 * @param message contains the data already mapped via <code>AuditMapper</code> and formatted by <code>AuditLogBuilder</code>
	 */
	void log(EventType eventType, boolean inbound, String message);

	/**
	 * Convert OpenSAML object to details for logging.
	 *
	 * @param xmlObject
	 * @return Extracted part of object for detail logging.
	 */
	String getAuditDetail(final XMLObject xmlObject);

	/**
	 * @param prefix optional prefix to use
	 * @return AuditLogBuilder to use for this logger.
	 */
	AuditLogBuilder createAuditLogBuilder(String prefix);

}
