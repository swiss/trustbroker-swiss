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

package swiss.trustbroker.config.dto;

import lombok.Data;

/**
 * Auditing configuration.
 * <br/>
 * Audit logging is done in two flavours:
 * <ol>
 *     <li>Regular audit logging with all data. Log groups
 *     <strong>swiss.trustbroker.audit.service.AuditLogger</strong> and
 *     <strong>swiss.trustbroker.audit.service.AuditLoggerDetail</strong></li>
 *     <li>Limited audit logging free of (CID) - optional. Log group:
 *     <strong>swiss.trustbroker.audit.service.OpsAuditLogger</strong></li>
 * </ol>
 * The idea behind the second variant is to have a log that be collected in a separate bucket (e.g. Splunk index) and made
 * available to people that must not have access to CID.
 *
 * @see OpsAuditConfig
 * @since 1.8.0
 */
@Data
public class AuditConfig {

	private OpsAuditConfig ops = new OpsAuditConfig();

}
