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

package swiss.trustbroker.common.saml.service;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.storage.StorageService;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;

/**
 * Holds a SAMLArtifactMap needed to store SAML objects for the SAML artifact binding
 */
@Slf4j
public class ArtifactCacheService {

	private final SAMLArtifactMap artifactMap;

	public ArtifactCacheService(Optional<StorageService> storageService, Duration artifactLifetime, Duration cleanupInterval) {
		artifactMap = OpenSamlUtil.createArtifactMap(storageService, artifactLifetime, cleanupInterval);
	}

	public SAMLArtifactMap getArtifactMap() {
		return artifactMap;
	}

	public Optional<SAMLObject> retrieveArtifact(String artifactId) {
		try {
			var mapEntry = artifactMap.get(artifactId);
			if (mapEntry == null) {
				log.error("Cannot find artifact={}", artifactId);
				return Optional.empty();
			}
			log.debug("Retrieved SAML artifactId={} artifact={} issuerId={} relyingPartyId={} samlMessage={}",
					artifactId, mapEntry.getArtifact(), mapEntry.getIssuerId(), mapEntry.getRelyingPartyId(),
					mapEntry.getSamlMessage().getClass().getName());
			return Optional.of(mapEntry.getSamlMessage());
		}
		catch (IOException ex) {
			throw new TechnicalException(String.format("Could not retrieve SAML artifact %s", artifactId), ex);
		}
	}

	public void removeArtifact(String artifactId) {
		try {
			artifactMap.remove(artifactId);
			log.debug("Removed artifactId={}", artifactId);
		}
		catch (IOException ex) {
			throw new TechnicalException(String.format("Could not remove SAML artifact %s", artifactId), ex);
		}
	}

}
