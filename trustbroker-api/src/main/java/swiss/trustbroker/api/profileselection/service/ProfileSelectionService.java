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

package swiss.trustbroker.api.profileselection.service;

import swiss.trustbroker.api.profileselection.dto.ProfileResponse;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionResult;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.api.sessioncache.dto.SessionState;

/**
 * A user that has different profiles may need to select the profile to use for authentication. (OIDC: prompt=select_account)
 * <br/>
 * This interface is preliminary and could still change.
 * <br/>
 * An implementation can be configured via Spring @Value binding or by injecting swiss.trustbroker.config.TrustbrokerProperties
 * and using swiss.trustbroker.config.dto.ProfileSelectionConfig (${trustbroker.config.profileSelection}).
 * <br>
 * Breaking changes:
 * <ul>
 *     <li>With 1.8.0 buildProfileResponse signature changed.</li>
 * </ul>
 */
public interface ProfileSelectionService {

	ProfileSelectionResult doInitialProfileSelection(ProfileSelectionData profileSelectionData,
			RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponseData, SessionState sessionState);

	ProfileSelectionResult doFinalProfileSelection(ProfileSelectionData profileSelectionData,
			RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponseData, SessionState sessionState);

	ProfileSelectionResult doSsoProfileSelection(ProfileSelectionData profileSelectionData,
			RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponseData, SessionState sessionState);

	ProfileResponse buildProfileResponse(ProfileSelectionData profileSelectionData, CpResponseData cpResponseData);

	boolean isValidSelectedProfile(ProfileSelectionData profileSelectionData, CpResponseData cpResponseData);
}
