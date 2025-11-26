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

package swiss.trustbroker.profileselection.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.profileselection.dto.ProfileResponse;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionResult;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.api.sessioncache.dto.SessionState;

/**
 * NO-OP fallback implementation of ProfileSelectionService, returns empty data.
 *
 * @see ProfileSelectionService
 */
@Service
@ConditionalOnMissingBean(ProfileSelectionService.class)
@Slf4j
public class NoOpProfileSelectionService implements ProfileSelectionService {

	@Override
	public ProfileSelectionResult doInitialProfileSelection(ProfileSelectionData profileSelectionData,
			RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponseData, SessionState sessionState) {
		log.debug("{}.doInitialProfileSelection called", this.getClass().getName());
		return ProfileSelectionResult.empty();
	}

	@Override
	public ProfileSelectionResult doFinalProfileSelection(ProfileSelectionData profileSelectionData,
			RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponseData, SessionState sessionState) {
		log.debug("{}.doFinalProfileSelection called", this.getClass().getName());
		return ProfileSelectionResult.empty();
	}

	@Override
	public ProfileSelectionResult doSsoProfileSelection(ProfileSelectionData profileSelectionData,
			RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponseData, SessionState sessionState) {
		log.debug("{}.doSsoProfileSelection called", this.getClass().getName());
		return ProfileSelectionResult.empty();
	}

	@Override
	public ProfileResponse buildProfileResponse(ProfileSelectionData profileSelectionData, CpResponseData cpResponseData) {
		return ProfileResponse.builder().build();
	}

	@Override
	public boolean isValidSelectedProfile(ProfileSelectionData profileSelectionData, CpResponseData cpResponseData) {
		return false;
	}
}
