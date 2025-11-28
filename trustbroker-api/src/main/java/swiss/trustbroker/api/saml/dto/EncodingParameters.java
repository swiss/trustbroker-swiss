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

package swiss.trustbroker.api.saml.dto;

import java.util.Collections;
import java.util.Map;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class EncodingParameters {

	/**
	 * Use artifact binding for SAML encoding.
	 * <br/>
	 * Default: false
	 */
	@Builder.Default
	private boolean useArtifactBinding = false;

	/**
	 * Use redirect binding for SAML encoding.
	 * <br/>
	 * Default: false
	 *
	 * @since 1.10.0
	 */
	@Builder.Default
	private boolean useRedirectBinding = false;

	/**
	 * Use SOAP binding for SAML encoding.
	 * <br/>
	 * Default: false
	 *
	 * @since 1.12.0
	 */
	@Builder.Default
	private boolean useSoapBinding = false;

	/**
	 * Optional signature algorithm for redirect encoding.
	 *
	 * @since 1.10.0
	 */
	private String signatureAlgorithm;

	@Builder.Default
	private Map<String, Object> templateParameters = Collections.emptyMap();

}
