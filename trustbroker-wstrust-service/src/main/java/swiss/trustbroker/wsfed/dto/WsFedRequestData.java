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

package swiss.trustbroker.wsfed.dto;

import java.time.Instant;

import lombok.Builder;
import lombok.Data;

/**
 * OIDC specific data for auditing.
 * <p>
 * (Can be replaced by an appropriate DTO used in other contexts when available.)
 */
@Data
@Builder
public class WsFedRequestData {

	private WsFedAction action; // required

	private String realm;

	private String authLevel;

	private Boolean forceAuth;

	private Instant timestamp;

	private String replyUrl;

	private String context;
}
