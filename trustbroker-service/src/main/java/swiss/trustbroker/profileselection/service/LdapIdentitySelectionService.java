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
import java.util.Objects;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.profileselection.dto.Profile;
import swiss.trustbroker.api.profileselection.dto.ProfileResponse;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionProperties;
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
@ConditionalOnBooleanProperty("trustbroker.config.ldap.enabled")
@ConditionalOnBooleanProperty("trustbroker.config.profileselection.enabled")
public class LdapIdentitySelectionService implements ProfileSelectionService {

	public static final String PROFILE_SEPARATOR = ":";

	private ApiSupport apiSupport;

	@Override
	public ProfileSelectionResult doInitialProfileSelection(ProfileSelectionData profileSelectionData,
															RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponseData, SessionState sessionState) {
		var profileSelection = profileSelectionData.getProfileSelectionProperties();
		if (ProfileSelectionService.isProfileSelectionDisabled(profileSelection)) {
			return ProfileSelectionResult.empty();
		}

		String profileSelector = profileSelection.getProfileSelector();
		var hasMultiProfile = hasMultiProfile(cpResponseData, profileSelector, profileSelection);
		var profileMode = ProfileSelectionMode.INTERACTIVE; // default
		if (hasMultiProfile) {
			if (ProfileSelectionMode.SILENT.name().equals(profileSelection.getProfileSelectionMode())) {
				log.warn("Multiple profiles detected for LDAPIdentitySelection, but SILENT mode not supported. Profile selection will be disabled.");
				return ProfileSelectionResult.empty();
			}
			// INTERACTIVE case only via UI using redirect approach
			log.info("Doing initial multi-profiles for LDAP rpIssuer={} oidcClientId={} subjectNameId={} "
							+ "having multiple profiles profileMode={}",
					relyingPartyConfig.getId(), profileSelectionData.getOidcClientId(), cpResponseData.getNameId(), profileMode);
			return ProfileSelectionResult.builder()
										 .redirectUrl(apiSupport.getProfileSelectionUrl(profileSelectionData.getExchangeId()))
										 .build();
		}

		// no profile handling required because user does not have multiple ones or the user has selected one
		final var result = ProfileSelectionResult.builder().build();
		result.setFilteredAttributes(cpResponseData.getUserDetailMap());

		log.info("Done initial single-profile for cpIssuer={} rpIssuer={} subjectNameId={} having multiple profiles profileMode={}",
				cpResponseData.getIssuerId(), relyingPartyConfig.getId(), cpResponseData.getNameId(),
				profileMode);

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
		int userProfileCount = getUserProfileCount(cpResponseData.getUserDetailMap(), profileSelector);
		var hasMultiProfile = hasMultiProfile(cpResponseData, profileSelector, profileSelection);
		var selectedProfileId = getSelectedProfileId(profileSelectionData);
		if (selectedProfileId == null) {
			var profileSelectionResult = ProfileSelectionResult.empty();
			// Multiple profile but no selection or user without a profile
			if (hasMultiProfile || userProfileCount == 0) {
				log.debug("Missing selectedProfileId for sessionId={} hasMultiProfile={}", sessionState.getId(), hasMultiProfile);
				return profileSelectionResult;
			}
		}

		final var unselectedProfileIds = getUnselectedProfileId(profileSelectionData, cpResponseData, selectedProfileId);
		var result = discardUnselectedProfileAttributeValues(cpResponseData, unselectedProfileIds);
		applyProfileTransformations(selectedProfileId, result, profileSelector, profileSelection.getOrganizationSelector());

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
							+ "having hasMultiProfile={} selectedProfileId={} profileMode={}",
					cpResponseData.getIssuerId(), relyingPartyConfig.getId(), cpResponseData.getNameId(),
					hasMultiProfile, selectedProfileId, profileSelection.getProfileSelectionMode());
		}
		return ProfileSelectionResult.builder()
									 .selectedProfileId(selectedProfileId)
									 .filteredAttributes(result)
									 .build();
	}

	private static boolean hasMultiProfile(CpResponseData cpResponseData, String profileSelector, ProfileSelectionProperties profileSelection) {
		var userProfileCount = getUserProfileCount(cpResponseData.getUserDetailMap(), profileSelector);
		if (userProfileCount < 2) {
			return false;
		}
		// Only check for existing users
		if (profileSelection.getOrganizationSelector() != null) {
			var organizationSelector = profileSelection.getOrganizationSelector();
			var orgCount = getUserProfileCount(cpResponseData.getUserDetailMap(), organizationSelector);
			if (orgCount == 0) {
				throw new TechnicalException(String.format("Organization was not found but required: organizationSelector=%s profileSelector=%s", organizationSelector, profileSelector));
			}
		}
		return true;
	}

	@Override
	public ProfileSelectionResult doSsoProfileSelection(ProfileSelectionData profileSelectionData,
														RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponseData,
														SessionState sessionState) {
		var profileSelection = profileSelectionData.getProfileSelectionProperties();
		if (ProfileSelectionService.isProfileSelectionDisabled(profileSelection)) {
			return ProfileSelectionResult.empty();
		}

		var profileSelector = profileSelection.getProfileSelector();
		var hasMultiProfile = hasMultiProfile(cpResponseData, profileSelector, profileSelection);
		var selectedProfileId = getSelectedProfileId(profileSelectionData);

		var result = ProfileSelectionResult.builder().build();
		// select again on refreshed data
		if (hasMultiProfile) {
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
		applyProfileTransformations(selectedProfileId, filteredProfileValues, profileSelector, profileSelection.getOrganizationSelector());

		log.info("Done SSO multi-profiles for cpIssuer={} rpIssuer={} subjectNameId={} "
						+ "having multiProfile={} selectedProfileId={} profileMode={}",
				cpResponseData.getIssuerId(), relyingPartyConfig.getId(), cpResponseData.getNameId(),
				hasMultiProfile, selectedProfileId, profileSelection.getProfileSelectionMode());

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
			var translationClaims = profileSelectionData.getProfileSelectionProperties().getTranslationAttributes();
			var profileName = profileSelectionData.getProfileSelectionProperties().getDisplayName();
			profiles = generateProfileObjects(userProfileIds, profileName, displayClaims, translationClaims, userDetails);
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
		log.debug("SelectedProfileId={} in ProfiledProfileName={} : result={}", selectedProfileId, userProfiles, match);
		return match;
	}

	static int getUserProfileCount(Map<AttributeName, List<String>> userDetails, String profileSelector) {
		var profileAttributes = DefinitionUtil.findListByNameOrNamespace(profileSelector, getLdapSource(), userDetails);
		return profileAttributes.size();
	}

	private static List<Profile> generateProfileObjects(List<String> profiles, String profileName, List<String> displayClaims,
														List<String> translationKeys, Map<AttributeName, List<String>> userDetails) {
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

			Map<String, Map<String, String>> translationInformation = new HashMap<>();
			getTranslationData(translationKeys, userDetails, profileId, translationInformation);
			log.debug("TranslationInformation={} for profile={}", translationInformation.size(), profileId);

			var name = profileId;
			if (profileName != null) {
				var profileDisplayNameValues = getDisplayValues(profileId, profileName, userDetails);
				if (!profileDisplayNameValues.isEmpty()) {
					name = profileDisplayNameValues.getFirst();
				}
			}

			var profile = Profile.builder()
								 .id(profileId)
								 .name(name)
								 .displayClaims(new LinkedHashMap<>(additionalInformation))
								 .translations(translationInformation)
								 .build();
			outputProfiles.add(profile);
		}
		return outputProfiles.stream()
							 .sorted(Comparator.comparing(Profile::getName))
							 .toList();
	}

	private static void getTranslationData(List<String> translationKeys, Map<AttributeName, List<String>> userDetails, String profileId, Map<String, Map<String, String>> translationInformation) {
		if (translationKeys != null) {
			for (var translationKey : translationKeys) {
				final var translationValues = getTranslationValues(profileId, translationKey, userDetails);
				if (!translationValues.isEmpty()) {
					translationInformation.put(translationKey, translationValues);
				} else {
					translationInformation.put(translationKey, Map.of(translationKey, translationKey));
				}
			}
		}
	}

	private static Map<String, String> getTranslationValues(String profileName, String translationKey, Map<AttributeName, List<String>> userDetails) {
		final var attributes = DefinitionUtil.findAttributesByNameStartsWith(userDetails, translationKey);
		Map<String, String> translationValues = new HashMap<>();
		for (var entry : attributes.entrySet()) {
			AttributeName key = entry.getKey();
			List<String> values = entry.getValue();
			if (values != null) {
				values = values.stream()
				               .filter(value -> isProfileAttribute(value, profileName))
				               .map(value -> getAttributeValueWithoutPrefix(profileName, value))
				               .toList();
				if (!values.isEmpty()) {
					translationValues.put(key.getName(), values.getFirst());
				}
			}
		}
		return translationValues;
	}

	private static String getAttributeValueWithoutPrefix(String profileName, String value) {
		var elements = value.split(PROFILE_SEPARATOR, 3);
		if (Objects.equals(value, profileName)) {
			return elements[0];
		}
		// profileId:attribute
		if (elements.length == 2) {
			return elements[1];
		}
		// profileId:orgId:attributes
		if (elements.length == 3) {
			return elements[2];
		}
		return value;
	}

	private static List<String> getDisplayValues(String profileName,
												 String attributeName,
												 Map<AttributeName, List<String>> userDetails) {
		final var values = DefinitionUtil.findValueByName(userDetails, attributeName);
		return values.stream()
					 .filter(value -> isProfileAttribute(value, profileName))
					 .map(value -> getAttributeValueWithoutPrefix(profileName, value))
					 .toList();
	}

	private String getSelectedProfileId(ProfileSelectionData profileSelectionData) {
		// Profile selection enabled but user did not select any profile = user has 1 profile
		return profileSelectionData.getSelectedProfileId();
	}

	private List<String> getUnselectedProfileId(ProfileSelectionData profileSelectionData, CpResponseData cpResponseData, String selectedProfileId) {
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
		             .filter(profileAttr -> unselectedProfileIds.stream().noneMatch(unselected -> isProfileAttribute(profileAttr, unselected)))
		             .toList();
	}

	static boolean isProfileAttribute(String profileAttr, String profilePrefix) {
		if (profileAttr.equals(profilePrefix)) {
			return true;
		}
		if (!profileAttr.contains(PROFILE_SEPARATOR)) {
			return false;
		}
		String[] profileAttrParts = profileAttr.split(PROFILE_SEPARATOR);
		String[] profilePrefixParts = new String[]{ profilePrefix };
		if (profilePrefix.contains(PROFILE_SEPARATOR)) {
			profilePrefixParts = profilePrefix.split(PROFILE_SEPARATOR);
		}

		if (profilePrefixParts.length > profileAttrParts.length) {
			return false;
		}
		for (int i = 0; i < profilePrefixParts.length; i++) {
			if (!profilePrefixParts[i].equals(profileAttrParts[i])) {
				return false;
			}
		}
		return true;
	}

	private static String getLdapSource() {
		return ClaimSourceUtil.buildClaimSource(ClaimSource.IDM, ExternalStores.LDAP.name());
	}

	private void applyProfileTransformations(String profileId, Map<AttributeName, List<String>> attributes, String profileSelector, String organizationSelector) {
		if (profileId == null || profileId.isBlank() || attributes == null || attributes.isEmpty()) {
			return;
		}
		// Cut prefixes generated in initial profile selection
		final String prefix = profileId + PROFILE_SEPARATOR;

		for (Map.Entry<AttributeName, List<String>> entry : attributes.entrySet()) {
			AttributeName attributeName = entry.getKey();
			List<String> transformedValues = getTransformedValues(profileSelector, organizationSelector, entry, attributeName, prefix);
			entry.setValue(transformedValues);
		}
	}

	private static List<String> getTransformedValues(String profileSelector, String organizationSelector, Map.Entry<AttributeName, List<String>> entry, AttributeName attributeName, String prefix) {
		List<String> transformedValues;
		if (organizationSelector != null && (profileSelector.equals(attributeName.getName()) || profileSelector.equals(attributeName.getNamespaceUri()))) {
			transformedValues = entry.getValue().stream()
									 .filter(Objects::nonNull)
									 .map(value -> value.split((PROFILE_SEPARATOR))[0])
									 .toList();
		}
		else {
			transformedValues = entry.getValue().stream()
									 .map(value -> value != null && isProfileAttribute(value, prefix)
											 ? value.substring(prefix.length()) : value)
									 .toList();
		}
		return transformedValues;
	}
}
