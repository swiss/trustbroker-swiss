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

package swiss.trustbroker.api.saml.service;

import jakarta.servlet.http.HttpServletResponse;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.security.credential.Credential;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.api.saml.dto.EncodingParameters;

/**
 * A service to render SAML requests and responses.
 * <br/>
 * An implementation is provided by trustbroker-service, generally there should be no need to change that.<br/>
 * This interface could still change.
 */
public interface OutputService {

	public <T extends RequestAbstractType> void sendRequest(T request,
			Credential credential, String relayState, String endpoint,
			HttpServletResponse httpServletResponse, EncodingParameters encodingParameters,
			DestinationType destinationType);

	public <T extends StatusResponseType> void sendResponse(T response,
			Credential credential, String requestRelayState, String endpoint,
			HttpServletResponse httpServletResponse, EncodingParameters encodingParameters,
			DestinationType destinationType);

}
