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

package swiss.trustbroker.saml.service;

import java.util.Optional;

import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.federation.xmlconfig.CounterParty;
import swiss.trustbroker.federation.xmlconfig.SubjectName;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.util.ClaimSourceUtil;

@Slf4j
class SubjectNameMapper {

	private SubjectNameMapper() {}

	static void adjustSubjectNameId(CpResponse cpResponse, CounterParty counterParty) {
		var nameIdMappings = counterParty.getSubjectNameMappings();
		var reason = "No matching mapping found";
		var cpIssuer = cpResponse.getIssuerId();
		Optional<SubjectName> subjectMapping = Optional.empty();
		if (nameIdMappings != null && nameIdMappings.getSubjects() != null) {
			if (!cpResponse.hasOriginalNameId() && nameIdMappings.getPreserve()) {
				reason = "NameID already set before"; // i.e. by a groovy script
			}
			else {
				subjectMapping = nameIdMappings.getSubjects()
						.stream()
						.filter(m -> mapSubject(m, counterParty, cpResponse))
						.findFirst();
			}
		}
		if (subjectMapping.isEmpty()) {
			log.info("Preserve federation principal for {} issuer={} cpIssuer={} cpNameId={} rpNameId={} using format={}: {}",
					counterParty.getShortType(), counterParty.getId(), cpIssuer, cpResponse.getOriginalNameId(),
					cpResponse.getNameId(), cpResponse.getNameIdFormat(), reason);
		}
	}

	private static boolean mapSubject(SubjectName subjectMapping, CounterParty counterParty, CpResponse cpResponse) {

		var nameIdClaim = subjectMapping.getClaim();
		var nameIdSource = subjectMapping.getSource();
		var claimSource = "";
		String nameId = null;

		if (nameIdClaim == null) {
			log.debug("SubjectName mapping claim not set for={}", counterParty.getId());
			return false;
		}

		// source = cpIssuer or  null
		var cpIssuer = cpResponse.getIssuerId();
		if (ClaimSourceUtil.isCpSource(cpIssuer, nameIdSource) || nameIdSource == null) {
			claimSource = "AttributesSelection";
			nameId = cpResponse.getAttribute(nameIdClaim);
		}

		// source = IDM/IdmQuery.name or null
		if (nameId == null) {
			claimSource = "UserDetailsSelection";
			nameId = getNameIdFromUserDetails(cpResponse, nameIdSource, nameIdClaim);
		}

		// source = PROPS or null
		if (nameId == null && (ClaimSource.PROPS.name().equals(nameIdSource) || nameIdSource == null)) {
			claimSource = "PropertiesSelection";
			nameId = cpResponse.getProperty(nameIdClaim);
		}

		if (nameId != null) {
			// also allow to adjust the format (relevant for some RPs)
			var nameIdFormat = subjectMapping.getFormat();
			if (nameIdFormat == null) {
				nameIdFormat = cpResponse.getNameIdFormat();
			}
			cpResponse.setMappedNameId(nameId);
			cpResponse.setNameId(nameId);
			cpResponse.setNameIdFormat(nameIdFormat);
			log.info("Change federation principal from cpIssuer={} cpNameId={} to {} issuer={} rpNameId={}"
							+ " using source='{} ({})' format={}",
					cpIssuer, cpResponse.getOriginalNameId(), counterParty.getShortType(), counterParty.getId(),
					cpResponse.getNameId(), nameIdClaim, claimSource, nameIdFormat);
			return true;
		}
		log.debug("Preserve federation principal for {} issuer={} cpIssuer={} cpNameId={} rpNameId={}"
						+ " using format={} because source={} is undefined",
				counterParty.getShortType(), counterParty.getId(), cpIssuer, cpResponse.getOriginalNameId(),
				cpResponse.getNameId(), cpResponse.getNameIdFormat(), nameIdClaim);
		return false;
	}

	static String getNameIdFromUserDetails(CpResponse cpResponse, String nameIdSource, String nameIdClaim) {
		if (nameIdSource != null && nameIdSource.startsWith(ClaimSource.IDM.name())) {
			return cpResponse.getUserDetail(nameIdClaim, nameIdSource);
		}
		return nameIdSource == null ? cpResponse.getUserDetail(nameIdClaim) : null;
	}

}
