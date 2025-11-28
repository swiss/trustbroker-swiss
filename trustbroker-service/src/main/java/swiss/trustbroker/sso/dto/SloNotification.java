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

package swiss.trustbroker.sso.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import swiss.trustbroker.federation.xmlconfig.SloResponse;

/**
 * Combines static configuration from SloUrl with dynamic SLO notification information
 */
@Data
@RequiredArgsConstructor
public class SloNotification {

	private final SloResponse slo;

	private String encodedUrl;

	private String samlLogoutRequest;

	private String samlRelayState;

	private String samlRedirectSignature;

	private String samlRedirectSignatureAlgorithm;

	private String samlHttpMethod;

}
