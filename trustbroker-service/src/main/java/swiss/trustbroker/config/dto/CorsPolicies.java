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

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * HTTP CORS configurations.
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS">CORS</a>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CorsPolicies {

	/**
	 * Origins permitted.
	 * <br/>
	 * Default: *
	 */
	private List<String> allowedOrigins;

	/**
	 * HTTP methods permitted.
	 * <br/>
	 * Default: GET, HEAD, OPTIONS
	 *
	 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods">Access-Control-Allow-Methods</a>
	 */
	private List<String> allowedMethods;

	/**
	 * Headers permitted.
	 * <br/>
	 * Default: Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method,
	 * Access-Control-Request-Headers, Authorization
	 *
	 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers">Access-Control-Allow-Headers</a>
	 */
	private List<String> allowedHeaders;

}
