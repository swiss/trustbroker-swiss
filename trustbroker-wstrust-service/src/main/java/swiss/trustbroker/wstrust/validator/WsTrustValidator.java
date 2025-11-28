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

package swiss.trustbroker.wstrust.validator;

import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestType;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;
import swiss.trustbroker.wstrust.dto.WsTrustValidationResult;

/**
 * Validator for WS-Trust requests.
 */
public interface WsTrustValidator {

	/**
	 * Check if this validator applies to the given type.
	 *
	 * @param requestType
	 * @return
	 */
	boolean applies(RequestType requestType);

	/**
	 * Perform validation of the RST request.
	 *
	 * @param requestSecurityToken request
	 * @param requestHeader        stored data from header (not null)
	 * @return Processed assertion (i.e. headerAssertion or one from the body) plus additional parameters.
	 * @throws RequestDeniedException if validation fails
	 */
	WsTrustValidationResult validate(RequestSecurityToken requestSecurityToken, SoapMessageHeader requestHeader);

}
