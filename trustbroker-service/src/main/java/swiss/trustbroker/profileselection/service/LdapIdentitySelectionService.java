/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.profileselection.dto.Profile;
import swiss.trustbroker.api.profileselection.dto.ProfileResponse;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionResult;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.api.sessioncache.dto.SessionState;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.federation.xmlconfig.ProfileSelectionMode;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.util.ClaimSourceUtil;
import swiss.trustbroker.util.ApiSupport;

/**
 * LDAP Identity Selection
 *
 * @see ProfileSelectionService
 */
@Service("ldap")
@AllArgsConstructor
@Slf4j
public class LdapIdentitySelectionService implements ProfileSelectionService {

	private static final String DEFAULT_PROFILE_SEPARATOR = "\\";

	private ApiSupport apiSupport;

	@Override
	public ProfileSelectionResult doInitialProfileSelection(ProfileSelectionData profileSelectionData,
			RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponseData, SessionState sessionState) {
		var profileSelection = profileSelectionData.getProfileSelectionProperties();
		if (ProfileSelectionService.isProfileSelectionDisabled(profileSelection)) {
			return ProfileSelectionResult.empty();
		}

		var profileCount = getUserProfileCount(cpResponseData.getUserDetailMap(), profileSelection.getProfileSelector());
		var profileMode = ProfileSelectionMode.INTERACTIVE; // default
		if (profileCount > 1) {
			if (ProfileSelectionMode.SILENT.name().equals(profileSelection.getProfileSelectionMode())) {
				log.warn("Multiple profiles detected for LDAPIdentitySelection, but SILENT mode not supported. Profile selection will be disabled.");
				return ProfileSelectionResult.empty();
			}
			// INTERACTIVE case only via UI using redirect approach
			log.info("Doing initial multi-profiles for LDAP rpIssuer={} oidcClientId={} subjectNameId={} "
							+ "having profileCount={} profileMode={}",
					relyingPartyConfig.getId(), profileSelectionData.getOidcClientId(), cpResponseData.getNameId(), profileCount,
					profileMode);
			return ProfileSelectionResult.builder().redirectUrl(
					apiSupport.getProfileSelectionUrl(profileSelectionData.getExchangeId())).build();
		}

		// no profile handling required because user does not have multiple ones or the user has selected one
		final var result = ProfileSelectionResult.builder().build();
		result.setFilteredAttributes(cpResponseData.getUserDetailMap());

		log.info("Done initial single-profile for cpIssuer={} rpIssuer={} subjectNameId={} having"
						+ " profileCount={} profileMode={}",
				cpResponseData.getIssuerId(), relyingPartyConfig.getId(), cpResponseData.getNameId(),
				profileCount, profileMode);

		return result;
	}

	@Override
	public ProfileSelectionResult doFinalProfileSelection(ProfileSelectionData profileSelectionData,
			RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponseData, SessionState sessionState) {
		var profileSelection = profileSelectionData.getProfileSelectionProperties();
		if (ProfileSelectionService.isProfileSelectionDisabled(profileSelection)) {
			return ProfileSelectionResult.empty();
		}

		var profileSelector = profileSelection.getProfileSelector();
		var profileCountBefore = getUserProfileCount(cpResponseData.getUserDetailMap(), profileSelector);
		var selectedProfileId = getSelectedProfileId(profileSelectionData);

		if (selectedProfileId == null) {
			var profileSelectionResult = ProfileSelectionResult.empty();
			if (profileCountBefore != 1) {
				log.debug("Missing selectedProfileId for sessionId={} profileCountBefore={}", sessionState.getId(), profileCountBefore);
				return profileSelectionResult;
			}
		}

		final var unselectedProfileIds = getUnselectedProfileId(profileSelectionData, cpResponseData, selectedProfileId);
		var result = discardUnselectedProfileAttributeValues(cpResponseData, unselectedProfileIds);
		applyProfileTransformations(selectedProfileId, result);

		if (profileSelectionData.isEnforceSingleProfile()) {
			var profileCountAfter = getUserProfileCount(result, profileSelector);
			if (profileCountAfter != 1) {
				throw new TechnicalException(String.format(
						"Profile filtering on requestedProfile=%s failed for sessionId=%s",
						selectedProfileId, sessionState.getId()));
			}
		}

		if (log.isInfoEnabled()) {
			log.info("Done final multi-profiles for cpIssuer={} rpIssuer={} subjectNameId={} "
							+ "having profileCount={} selectedProfileId={} profileMode={}",
					cpResponseData.getIssuerId(), relyingPartyConfig.getId(), cpResponseData.getNameId(),
					profileCountBefore, selectedProfileId, profileSelection.getProfileSelectionMode());
		}
		return ProfileSelectionResult.builder()
									 .selectedProfileId(selectedProfileId)
									 .filteredAttributes(result)
									 .build();
	}

	@Override
	public ProfileSelectionResult doSsoProfileSelection(ProfileSelectionData profileSelectionData,
														RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponseData,
														SessionState sessionState) {
		var profileSelection = profileSelectionData.getProfileSelectionProperties();
		if (ProfileSelectionService.isProfileSelectionDisabled(profileSelection)) {
			return ProfileSelectionResult.empty();
		}

		var profileCount = getUserProfileCount(cpResponseData.getUserDetailMap(), profileSelection.getProfileSelector());
		var selectedProfileId = getSelectedProfileId(profileSelectionData);

		var result = ProfileSelectionResult.builder().build();
		// select again on refreshed data
		if (profileCount > 1) {
			if (ProfileSelectionMode.SILENT.name().equals(profileSelection.getProfileSelectionMode())) {
				log.warn("Multiple profiles detected for LDAPIdentitySelection, but SILENT mode not supported. Profile selection will be disabled.");
				result.setFilteredAttributes(cpResponseData.getUserDetailMap());
			}
			else {
				return ProfileSelectionResult.builder()
											 .redirectUrl(apiSupport.getProfileSelectionUrl(sessionState.getId()))
											 .build();
			}
		}

		final var unselectedProfileIds = getUnselectedProfileId(profileSelectionData, cpResponseData, selectedProfileId);
		var filteredProfileValues = discardUnselectedProfileAttributeValues(cpResponseData, unselectedProfileIds);
		applyProfileTransformations(selectedProfileId, filteredProfileValues);

		log.info("Done SSO multi-profiles for cpIssuer={} rpIssuer={} subjectNameId={} "
						+ "having profileCount={} selectedProfileId={} profileMode={}",
				cpResponseData.getIssuerId(), relyingPartyConfig.getId(), cpResponseData.getNameId(),
				profileCount, selectedProfileId, profileSelection.getProfileSelectionMode());

		return ProfileSelectionResult.builder()
				.selectedProfileId(selectedProfileId)
				.filteredAttributes(filteredProfileValues)
				.build();
	}

	@Override
	public ProfileResponse buildProfileResponse(ProfileSelectionData profileSelectionData, CpResponseData cpResponseData) {
		List<Profile> profiles = new ArrayList<>();

		if (cpResponseData != null) {
			var userDetails = cpResponseData.getUserDetailMap();
			var userProfileIds = DefinitionUtil.findListByNameOrNamespace(profileSelectionData.getProfileSelectionProperties().getProfileSelector(), getLdapSource(), userDetails);
			if (userProfileIds.isEmpty()) {
				return ProfileResponse.builder().build();
			}
		 	var displayClaims = getDisplayClaims(profileSelectionData);
			var profileName = profileSelectionData.getProfileSelectionProperties().getDisplayName();
			profiles = generateProfileObjects(userProfileIds, profileName, displayClaims,  userDetails);
		}
		return ProfileResponse.builder()
				.id(profileSelectionData.getSelectedProfileId())
				.profiles(profiles)
				.application(profileSelectionData.getApplicationName())
				.build();
	}

	private List<String> getDisplayClaims(ProfileSelectionData profileSelectionData) {
		return profileSelectionData.getProfileSelectionProperties().getDisplayClaims();
	}

	@Override
	public boolean isValidSelectedProfile(ProfileSelectionData profileSelectionData, CpResponseData cpResponseData) {
		var selectedProfileId = profileSelectionData.getSelectedProfileId();
		if (selectedProfileId == null) {
			return true;
		}
		if (cpResponseData == null) {
			log.debug("No CpResponse SelectedProfileId={} not considered valid", selectedProfileId);
			return false;
		}
		var userDetails = cpResponseData.getUserDetailMap();
		var userProfiles = DefinitionUtil.findValueByName(userDetails, profileSelectionData.getProfileSelectionProperties().getProfileSelector());
		if (userProfiles.isEmpty()) {
			log.debug("No ProfiledProfileName SelectedProfileId={} not considered valid", selectedProfileId);
			return false;
		}
		boolean match = userProfiles.stream().anyMatch(name -> name.equals(selectedProfileId));
		log.debug("SelectedProfileId={} in ProfiledProfileName={} : result={}" , selectedProfileId, userProfiles, match);
		return match;
	}

	static int getUserProfileCount(Map<AttributeName, List<String>> userDetails, String profileSelector) {
		var profileAttributes = DefinitionUtil.findListByNameOrNamespace(profileSelector, getLdapSource(), userDetails);
		return profileAttributes.size();
	}

	private static List<Profile> generateProfileObjects(List<String> profiles,String profileName, List<String> displayClaims,
														Map<AttributeName, List<String>> userDetails) {
		List<Profile> outputProfiles = new ArrayList<>();
		for (var profileId : profiles) {
			Map<String, List<String>> additionalInformation = new HashMap<>();
			if (displayClaims != null) {
				for (var displayClaim : displayClaims) {
					final var displayValues = getDisplayValues(profileId, displayClaim, userDetails);
					if (!displayValues.isEmpty()) {
						additionalInformation.put(displayClaim, displayValues);
					}
				}
			}
			var name = profileId;
			if (profileName != null) {
				var profileDisplayNameValues = getDisplayValues(profileId, profileName, userDetails);
				if (!profileDisplayNameValues.isEmpty()) {
					name = profileDisplayNameValues.get(0);
				}
			}
			var profile = Profile.builder()
								 .id(profileId)
								 .name(name)
								 .displayClaims(new LinkedHashMap<>(additionalInformation))
								 .build();
			outputProfiles.add(profile);
		}
		return outputProfiles.stream()
				.sorted(Comparator.comparing(Profile::getName))
				.toList();
	}

	private static List<String> getDisplayValues(String profileName,
												 String attributeName,
												 Map<AttributeName, List<String>> userDetails) {
		final var values = DefinitionUtil.findValueByName(userDetails, attributeName);
		return values.stream()
					 .filter(value -> value.contains(profileName))
					 .map(value -> {
						 int separatorIndex = value.indexOf(DEFAULT_PROFILE_SEPARATOR);
						 return separatorIndex != -1 ?
								 value.substring(separatorIndex + DEFAULT_PROFILE_SEPARATOR.length()) :
								 value;
					 })
					 .toList();
	}

	private String getSelectedProfileId(ProfileSelectionData profileSelectionData) {
        // Profile selection enabled but user did not select any profile = user has 1 profile
        return profileSelectionData.getSelectedProfileId();
	}

	private List<String> getUnselectedProfileId(ProfileSelectionData profileSelectionData, CpResponseData cpResponseData, String selectedProfileId){
		if (selectedProfileId == null) {
			return new ArrayList<>();
		}
		final var userDetails = cpResponseData.getUserDetailMap();
		final var userProfiles = DefinitionUtil.findListByNameOrNamespace(profileSelectionData.getProfileSelectionProperties().getProfileSelector(),
				getLdapSource(), userDetails);

		return userProfiles.stream()
						   .map(String::trim)
						   .filter(profile -> !profile.equals(selectedProfileId.trim()))
						   .distinct()
						   .toList();
	}

	/**
	 * Drop all attribute values that start with any of the given unselected profile IDs + separator.
	 * Values without any profile prefix are kept as-is.
	 */
	private Map<AttributeName, List<String>> discardUnselectedProfileAttributeValues(CpResponseData cpResponseData, List<String> unselectedProfileIds) {
		var userDetails = cpResponseData.getUserDetailMap();
		if (userDetails == null) {
			throw new TechnicalException("User details are missing in CpResponse with issuer" + cpResponseData.getIssuerId());
		}

		Map<AttributeName, List<String>> filteredMap = new HashMap<>();
		for (Map.Entry<AttributeName, List<String>> entry : userDetails.entrySet()) {
			var filteredValues = filterProfiledAttributeValues(entry, unselectedProfileIds);
			if (!filteredValues.isEmpty()) {
				filteredMap.put(entry.getKey(), filteredValues);
			}
		}
		return filteredMap;
	}

	private List<String> filterProfiledAttributeValues(Map.Entry<AttributeName, List<String>> entry, List<String> unselectedProfileIds) {
		List<String> values = entry.getValue();
		if (values == null || values.isEmpty()) {
			return List.of();
		}

		if (unselectedProfileIds == null || unselectedProfileIds.isEmpty()) {
			return List.copyOf(values);
		}
		var key = entry.getKey();
		if (key.getSource() != null && (!key.getSource().equals(ClaimSource.IDM.name()) && !key.getSource().equals(getLdapSource()))) {
			return List.copyOf(values);
		}

		return values.stream()
					.filter(profileAttr -> unselectedProfileIds.stream().noneMatch(profileAttr::contains))
					.toList();
	}

	private static String getLdapSource() {
		return ClaimSourceUtil.buildClaimSource(ClaimSource.IDM, ExternalStores.LDAP.name());
	}

	private void applyProfileTransformations(String profileId, Map<AttributeName, List<String>> attributes){
		if (profileId == null || profileId.isBlank() || attributes == null || attributes.isEmpty()) {
			return;
		}

		final String prefix = profileId + DEFAULT_PROFILE_SEPARATOR;

		for (Map.Entry<AttributeName, List<String>> entry : attributes.entrySet()) {
			List<String> transformedValues = entry.getValue().stream()
												  .map(value -> value != null && value.startsWith(prefix)
														  ? value.substring(prefix.length()) : value)
												  .toList();
			entry.setValue(transformedValues);
		}
	}
}
