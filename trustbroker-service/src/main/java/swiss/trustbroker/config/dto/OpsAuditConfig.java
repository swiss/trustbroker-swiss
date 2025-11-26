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

import java.util.HashMap;
import java.util.Map;

import lombok.Data;

/**
 * CID (client identifying data) auditing configuration.
 *
 * @since 1.8.0
 */
@Data
public class OpsAuditConfig {

	/**
	 * Enable CID free logging on the log group <strong>swiss.trustbroker.audit.service.OpsAuditLogger</strong>.
	 * <br/>
	 * You need to enable the log group as well
	 * This is not controlled by the log level of the log group alone as commonly INFO is enabled for the
	 * whole of <strong>swiss.trustbroker</strong>.
	 * <br/>
	 * Default: false
	 */
	private boolean enabled = false;

	/**
	 * Fields to be considered CID by property names of <strong>swiss.trustbroker.audit.dto.AuditDto</strong>.
	 * <br/>
	 * Note: This map might potentially be used to define defaults for Definitions, hence the boolean value.
	 * Currently, setting a field to false is equivalent to not configuring it,
	 * you might still use that to document that you considered the field not CID.
	 */
	private Map<String, Boolean> cidFields = new HashMap<>();

}
