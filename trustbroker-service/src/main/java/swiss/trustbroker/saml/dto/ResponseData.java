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

package swiss.trustbroker.saml.dto;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.opensaml.saml.saml2.core.StatusResponseType;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureContext;

@Data
@RequiredArgsConstructor(staticName = "of")
@Builder
public class ResponseData <T extends StatusResponseType> {

	private final T response;

	private final String relayState;

	private final SignatureContext signatureContext;

	public SamlBinding getBinding() {
		return signatureContext != null ? signatureContext.getBinding() : null;
	}
}
