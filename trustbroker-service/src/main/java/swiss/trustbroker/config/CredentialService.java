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

package swiss.trustbroker.config;

import java.io.File;
import java.nio.file.Path;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.security.credential.Credential;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.common.util.DirectoryUtil;
import swiss.trustbroker.federation.xmlconfig.SignerKeystore;
import swiss.trustbroker.federation.xmlconfig.SignerStore;
import swiss.trustbroker.federation.xmlconfig.SignerTruststore;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartySetupUtil;

@Service
@AllArgsConstructor
@Slf4j
public class CredentialService {

	private static final String CONFIG_CACHE_KEYSTORE_SUBPATH = GitService.CONFIGURATION_PATH_SUB_DIR_LATEST + "keystore/";

	private static final String CONFIG_CACHE_DEFINITION_SUBPATH =
			GitService.CONFIGURATION_PATH_SUB_DIR_LATEST + RelyingPartySetupUtil.DEFINITION_PATH;

	private final TrustBrokerProperties trustBrokerProperties;

	public Credential checkAndLoadCert(SignerKeystore signerKeystore, String urn, String subPath) {
		if (signerKeystore == null) {
			throw new TechnicalException(String.format("Certificate invalid: Missing Signer Keystore for urn=%s", urn));
		}
		checkCertPath(signerKeystore.getCertPath(), urn);
		return checkAndLoadCert(signerKeystore, subPath);
	}

	private static void checkCertPath(String path, String urn) {
		if (StringUtils.isBlank(path)) {
			throw new TechnicalException(String.format("Certificate password is missing for urn=%s", urn));
		}
	}

	private Credential checkAndLoadCert(SignerStore store, String subPath) {
		resolveStorePaths(store, subPath);
		return CredentialReader.getCredential(store.getResolvedCertPath(), store.getCertType(),
				store.getPassword(), store.getAlias(), store.getResolvedKeyPath());
	}

	private void resolveStorePaths(SignerStore store, String subPath) {
		var basePath = resolvePath(store.getCertPath(), subPath);
		var resolvedCertPath = new File(basePath, store.getCertPath()).getPath();
		store.setResolvedCertPath(resolvedCertPath);
		if (store.getKeyPath() != null) {
			// key is always loaded from the same path as cert
			store.setResolvedKeyPath(basePath + store.getKeyPath());
		}
	}

	private String resolvePath(String certPath, String subPath) {
		// see ReferenceHolder for the order
		var configPath = trustBrokerProperties.getConfigurationPath();
		if (StringUtils.isNotEmpty(subPath)) {
			// 1. relative path in definition
			var path = configPath + CONFIG_CACHE_DEFINITION_SUBPATH + subPath;
			if (certificateExists(certPath, path)) {
				return path;
			}
			// 2. relative path in keystore
			path = configPath + CONFIG_CACHE_KEYSTORE_SUBPATH + subPath;
			if (certificateExists(certPath, path)) {
				return path;
			}
		}
		// 3. default directory
		var path = configPath + CONFIG_CACHE_KEYSTORE_SUBPATH;
		if (certificateExists(certPath, path)) {
			return path;
		}
		throw new TechnicalException(String.format("Failed to load cert='%s' in path='%s' or subPath='%s'", certPath, path, subPath));
	}

	private static boolean certificateExists(String certPath, String path) {
		var certFile = Path.of(path, certPath).toString();
		if (DirectoryUtil.existsOnFilesystemOrClasspath(certFile)) {
			log.trace("Found cert={} on path={}", certPath, path);
			return true;
		}
		return false;
	}

	public List<Credential> checkAndLoadTrustCredential(SignerTruststore signerTruststore, String urn, String subPath) {
		if (signerTruststore == null) {
			throw new TechnicalException(String.format("Certificate invalid: Missing SignerTruststore for urn=%s", urn));
		}
		checkCertPath(signerTruststore.getCertPath(), urn);
		return loadTrustCredential(signerTruststore, subPath);
	}

	private List<Credential> loadTrustCredential(SignerStore store, String subPath) {
		resolveStorePaths(store, subPath);
		return CredentialReader.readTrustCredentials(
				store.getResolvedCertPath(), store.getCertType(), store.getPassword(), store.getAlias());
	}
}
