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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * HTTP Frame Options configuration.
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options">X-Frame-Options</a>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FrameOptionsPolicies {

	public static final String DEFAULT_FRAME_OPTIONS = "SAMEORIGIN";

	/**
	 * No further differentiation here as the FE, API, and SAML URLs are used together.
	 * <br/>
	 * Default: SAMEORIGIN
 	 */
	@Builder.Default
	private String fallback = DEFAULT_FRAME_OPTIONS;

	/**
	 * /app/device and other api services might run in an application iframe so switch from deny to same origin.
	 * Does not work on: Redirects (DENY default applies there still).
	 * We make sure in OidcTxResponseWrapper to set SAMEORIGIN instead of DENY just in case.
	 * <br/>
	 * Default: SAMEORIGIN
 	 */
	@Builder.Default
	private String oidc = DEFAULT_FRAME_OPTIONS;

}
