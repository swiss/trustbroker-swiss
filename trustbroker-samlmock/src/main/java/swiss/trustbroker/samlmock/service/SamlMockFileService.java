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

package swiss.trustbroker.samlmock.service;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.security.credential.Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.exception.TrustBrokerException;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.samlmock.SamlMockProperties;

@Component
@AllArgsConstructor
@Slf4j
public class SamlMockFileService {

	private static final String REQUEST_DIRECTORY = "/request/";

	private static final String RESPONSE_DIRECTORY = "/response/";

	private final GitService gitService;

	private final SamlMockProperties properties;

	private final Map<String, List<String>> nameCache;

	private final Map<String, byte[]> contentCache;

	private final Map<String, Credential> credentialCache;

	@Autowired
	public SamlMockFileService(GitService gitService, SamlMockProperties properties) {
		this.gitService = gitService;
		this.properties = properties;
		contentCache = new ConcurrentHashMap<>();
		nameCache = new ConcurrentHashMap<>();
		credentialCache = new ConcurrentHashMap<>();
	}

	public List<String> getMockRequestNames() {
		return getMockFileNames(REQUEST_DIRECTORY);
	}

	public List<String> getMockResponseNames() {
		return getMockFileNames(RESPONSE_DIRECTORY);
	}

	private List<String> getMockFileNames(String directory) {
		log.trace("Getting mock files from directory={}", directory);
		if (properties.isCacheMockFiles()) {
			return nameCache.computeIfAbsent(directory, this::loadFiles);
		}
		else {
			return loadFiles(directory);
		}
	}

	public byte[] getMockRequestFile(String mockFile) {
		return getMockFile(mockFile, REQUEST_DIRECTORY);
	}

	public byte[] getMockResponseFile(String mockFile) {
		return getMockFile(mockFile, RESPONSE_DIRECTORY);
	}

	private byte[] getMockFile(String mockFile, String directory) {
		var mockFilePath = getMockDirectoryPath(directory) + mockFile;
		log.trace("Getting mockFile={}", mockFilePath);
		if (properties.isCacheMockFiles()) {
			return contentCache.computeIfAbsent(mockFilePath, SamlMockFileService::readFile);
		}
		else {
			return readFile(mockFilePath);
		}
	}

	private static byte[] readFile(String mockFile) {
		try {
			var result = SamlIoUtil.getInputStreamFromFile(mockFile).readAllBytes();
			log.debug("Found mockFile={} size={}", mockFile, result.length);
			if (log.isTraceEnabled()) {
				log.trace("Using mockFile={} content={}", mockFile, new String(result, StandardCharsets.UTF_8));
			}
			return result;
		}
		catch (IOException e) {
			log.error("Reading config file={} failed: ex={}", mockFile, e.getMessage(), e);
			throw new TechnicalException(String.format("Reading config file=%s failed", mockFile), e);
		}
	}

	private List<String> loadFiles(String directory) {
		return listDirectoryContent(getMockDirectoryPath(directory));
	}

	public void refreshMockData() {
		try {
			var configCache = GitService.getConfigCachePath();
			var cacheDir = new File(configCache);
			if (cacheDir.exists() && cacheDir.isDirectory()) {
				gitService.pullConfiguration();
			}
			else {
				gitService.cloneConfiguration();
			}
			clearCache();
			log.info("Mock data refreshed");
		}
		catch (TrustBrokerException e) {
			log.error("Handling config refresh failed: {}", e.getInternalMessage());
			throw e;
		}
	}

	private void clearCache() {
		if (properties.isCacheMockFiles()) {
			nameCache.clear();
			contentCache.clear();
			credentialCache.clear();
			log.debug("Mock caches cleared");
		}
	}

	private static List<String> listDirectoryContent(String directory) {
		var dir = new File(directory);
		var files = dir.list();
		if (files != null && files.length > 0) {
			Arrays.sort(files);
		}
		else {
			log.info("No files loaded from {}", dir.getAbsolutePath());
		}
		if (log.isDebugEnabled()) {
			log.debug("directory={} contains files={}", dir.getAbsolutePath(),
					files != null ? Arrays.asList(files) : null);
		}
		var result = files != null ? Arrays.asList(files) : Collections.<String>emptyList();
		log.debug("Found {} files in directory={} files={}", result.size(), directory, result);
		return result;
	}

	private String getMockDirectoryPath(String which) {
		return properties.getMockDataDirectory() + which;
	}


	public Credential getAuthnRequestCredential() {
		return getCredential(getSpSignerKeystorePath(), properties.getSpSignerPassword(), properties.getSpSignerAlias());
	}

	public Credential getResponseCredential() {
		return getCredential(getIdpSignerKeystorePath(), properties.getIdpSignerPassword(), properties.getIdpSignerAlias());
	}

	public Credential getEncryptionCredential() {
		return getCredential(getEncryptionKeystorePath(), properties.getEncryptionPassword(), properties.getEncryptionAlias());
	}

	private Credential getCredential(String keystorePath, String password, String alias) {
		log.trace("Getting keystorePath={} alias={}", keystorePath, alias);
		if (properties.isCacheMockFiles()) {
			return credentialCache.computeIfAbsent(keystorePath, path -> readCredential(path, password, alias));
		}
		else {
			return readCredential(keystorePath, password, alias);
		}
	}

	private Credential readCredential(String keystorePath, String password, String alias) {
		try {
			// key shall be stored along cert
			var credential = CredentialReader.createCredential(
					keystorePath,
					null,
					password,
					alias,
					keystorePath);
			log.debug("Found keystorePath={} alias={}", keystorePath, alias);
			return credential;
		}
		catch (TrustBrokerException e) {
			log.error("Reading keystorePath={} failed: {}", keystorePath, e.getInternalMessage());
			throw e;
		}
	}

	private String getSpSignerKeystorePath() {
		return properties.getKeystoreDirectory() + properties.getSpSignerKeystore();
	}

	private String getIdpSignerKeystorePath() {
		return properties.getKeystoreDirectory() + properties.getIdpSignerKeystore();
	}

	private String getEncryptionKeystorePath() {
		return properties.getKeystoreDirectory() + properties.getEncryptionKeystore();
	}

}
