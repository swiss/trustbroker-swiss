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
 * Cookie configuration.
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie">Set-Cookie</a>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CookieProperties {

	/**
	 * Cookie name
	 */
	private String name;

	/**
	 * Optional cookie path
	 */
	private String path;

	/**
	 * Optional cookie domain
	 */
	private String domain;

	/**
	 * Optional cookie maxAge
	 */
	private Integer maxAge;

	/**
	 * Optional cookie permitted values.
	 */
	private String[] values;

	/**
	 * Optional cookie default value.
	 */
	private String defaultValue;

	/**
	 * Optional cookie secure flag.
	 */
	private Boolean secure;

	/**
	 * Optional cookie HTTP only flag.
	 */
	private Boolean httpOnly;

	/**
	 * Optional cookie sameSite flag.
	 */
	private String sameSite;

}
