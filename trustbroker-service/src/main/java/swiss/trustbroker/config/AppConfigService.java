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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.security.credential.Credential;
import org.springframework.cloud.endpoint.event.RefreshEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.setup.config.BootstrapProperties;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.service.XmlConfigStatusService;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.federation.xmlconfig.SsoGroupSetup;
import swiss.trustbroker.homerealmdiscovery.service.WebResourceProvider;
import swiss.trustbroker.homerealmdiscovery.util.ClaimsProviderUtil;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartySetupUtil;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.oidc.ClientConfigInMemoryRepository;
import swiss.trustbroker.oidc.OidcEncryptionKeystoreService;
import swiss.trustbroker.oidc.cache.service.OidcMetadataCacheService;
import swiss.trustbroker.script.service.ScriptService;

@Service
@AllArgsConstructor
@Slf4j
public class AppConfigService {

	@SuppressWarnings("java:S1075")
	private static final String CONFIG_CACHE_PATH = "/configCache/trustbroker-inventories/";

	private static final String CONFIG_CACHE_DEFINITION_SUBPATH =
			GitService.CONFIGURATION_PATH_SUB_DIR_LATEST + RelyingPartySetupUtil.DEFINITION_PATH;

	private final ApplicationEventPublisher eventPublisher;

	private final TrustBrokerProperties trustBrokerProperties;

	private final GitService gitService;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final ScriptService scriptService;

	private final ClientConfigInMemoryRepository clientConfigInMemoryRepository;

	private final List<IdmQueryService> idmQueryServices;

	private final MetricsService metricsService;

	private final XmlConfigStatusService xmlConfigStatusService;

	private final OidcMetadataCacheService oidcMetadataCacheService;

	private final WebResourceProvider resourceProvider;

	private final CredentialService credentialService;

	private final OidcEncryptionKeystoreService oidcEncryptionKeystoreService;

	public int checkAndUpdate() {
		var changed = mustUpdateFiles();
		if (changed != 0) {
			gitService.rolloverConfig(trustBrokerProperties.getConfigurationPath());
			refresh();
			trustBrokerProperties.setGitParamsFromEnv();
			// load up-to-date scripts for validation
			scriptService.prepareRefresh();
			checkAndUpdateMapping();
			checkAndUpdateOidcRegistry(relyingPartyDefinitions.getRelyingPartySetup());
			// load scripts, this MUST be last as the refresh will swap the script registry, and we are not transactional here
			scriptService.activateRefresh();
			updateMetrics();
			resourceProvider.flushCache();
			// OIDC remote calls at the end
			oidcMetadataCacheService.triggerRefreshConfigurations();
		}
		return changed;
	}

	public void updateMetrics() {
		var configStatus = xmlConfigStatusService.getConfigStatus();
		metricsService.gauge(MetricsService.CONFIG_STATUS_LABEL + "cp", configStatus.getClaimsProviders().size());
		metricsService.gauge(MetricsService.CONFIG_STATUS_LABEL + "rp", configStatus.getRelyingParties().size());
	}

	public void checkClaimAndRpMatch(RelyingPartySetup relyingPartySetup, SsoGroupSetup ssoGroupSetup) {
		checkRpSsoIntegrity(relyingPartySetup, ssoGroupSetup);
	}

	static void checkRpSsoIntegrity(RelyingPartySetup relyingPartySetup, SsoGroupSetup ssoGroupSetup) {
		for (RelyingParty rp : relyingPartySetup.getRelyingParties()) {
			if (rp.isSsoEnabled()) {
				var ssoGroupName = rp.getSso().getGroupName();
				if (StringUtils.isEmpty(ssoGroupName)) {
					log.error("RelyingParty with rpId={} enables SSO without an SSO group", rp.getId());
					rp.initializedValidationStatus().addError("RelyingParty enables SSO without an SSO group");
				} else if (groupMissing(ssoGroupSetup, ssoGroupName)) {
					log.error("SSO definition for ssoGroupName={} required for RelyingParty with rpId={} not found",
							ssoGroupName, rp.getId());
					rp.initializedValidationStatus().addError(
							String.format("SSO definition for ssoGroupName=%s required for RelyingParty not found", ssoGroupName));
				}
			}
		}
	}

	private static boolean groupMissing(SsoGroupSetup ssoGroupSetup, String ssoGroupName) {
		return ssoGroupSetup == null ||
				ssoGroupSetup.getSsoGroups().stream().noneMatch(group -> ssoGroupName.equals(group.getName()));
	}

	public static String getConfigCachePath(String configurationPath) {
		// developer workaround makings service startable on Windows (C drive only)
		if (configurationPath.startsWith("C:\\")) {
			configurationPath = configurationPath.replace("\\", "/").replace("C:", "/c");
		}
		int last = configurationPath.lastIndexOf("/");
		return configurationPath.substring(0, last) + CONFIG_CACHE_PATH;
	}

	public void refresh() {
		log.debug("Refreshing application config");
		eventPublisher.publishEvent(new RefreshEvent(this, "RefreshEvent", "Refreshing scope"));
	}

	private void checkAndUpdateMapping() {
		var claimsDefinitionMapping = trustBrokerProperties.getClaimsDefinitionMapping();
		var relyingPartySetupPath = trustBrokerProperties.getRelyingPartySetup();
		var claimsProviderSetupPath = trustBrokerProperties.getClaimsProviderSetup();
		var ssoGroupSetupPath = trustBrokerProperties.getSsoGroupSetup();

		var configurationPath = trustBrokerProperties.getConfigurationPath();
		var newConfigPath = getConfigCachePath(configurationPath) +
				BootstrapProperties.getSpringProfileActive() + File.separatorChar;

		var claimsProviderDefinitions = ClaimsProviderUtil.loadClaimsProviderDefinitions(
				newConfigPath + claimsDefinitionMapping);

		var claimsProviderSetup = ClaimsProviderUtil.loadClaimsProviderSetup(
				newConfigPath + claimsProviderSetupPath);

		var relyingPartySetup = ClaimsProviderUtil.loadRelyingPartySetup(
				newConfigPath + relyingPartySetupPath);

		var ssoGroupSetup = ClaimsProviderUtil.loadSsoGroups(newConfigPath + ssoGroupSetupPath);

		if (claimsProviderDefinitions != null) {
			relyingPartyDefinitions.setClaimsProviderDefinitions(claimsProviderDefinitions);
		}

		if (claimsProviderSetup != null) {
			checkAndLoadCpCertificates(claimsProviderSetup);
			validateScripts(claimsProviderSetup);
			filterInvalidClaimsParties(claimsProviderSetup);
			relyingPartyDefinitions.setClaimsProviderSetup(claimsProviderSetup);
		}

		if (ssoGroupSetup != null) {
			relyingPartyDefinitions.setSsoGroupSetup(ssoGroupSetup);
		}

		if (relyingPartySetup != null) {
			Collection<RelyingParty> claimRules = relyingPartySetup.getRelyingParties();
			RelyingPartySetupUtil.loadRelyingParty(claimRules, trustBrokerProperties.getConfigurationPath()
							+ CONFIG_CACHE_DEFINITION_SUBPATH, newConfigPath, trustBrokerProperties, idmQueryServices,
					scriptService, claimsProviderSetup, claimsProviderDefinitions);
			checkAndLoadRelyingPartyCertificates(relyingPartySetup);
			checkRpSsoIntegrity(relyingPartySetup, ssoGroupSetup);
			filterInvalidRelyingParties(relyingPartySetup);
			relyingPartyDefinitions.setRelyingPartySetup(relyingPartySetup);
			relyingPartyDefinitions.loadOidcConfiguration(trustBrokerProperties.getOidc());
			relyingPartyDefinitions.loadAccessRequestConfigurations();
		}
	}

	public void checkAndUpdateOidcRegistry(RelyingPartySetup relyingPartySetup) {
		log.info("OIDC provider registry update for relyingPartyCount={} items", relyingPartySetup.getRelyingParties().size());
		var oidcClientCount = 0;
		for (var relyingParty : relyingPartySetup.getRelyingParties()) {
			for (var oidcClient : relyingParty.getOidcClients()) {
				// INFO logs and caches spring registered OIDC clients
				try {
					clientConfigInMemoryRepository.findByClientId(oidcClient.getId());
					oidcClientCount += 1;
				} catch (RuntimeException ex) {
					log.error("Invalid RP={} oidcClientId={}: {}", relyingParty.getId(), oidcClient.getId(), ex);
					relyingParty.invalidate(ex);
				}
			}
		}
		log.info("OIDC provider registry update done for oidcClientCount={} items", oidcClientCount);
	}

	public void checkAndLoadCpCertificates(ClaimsProviderSetup claimsProviderSetup) {
		for (ClaimsParty claimsParty : claimsProviderSetup.getClaimsParties()) {
			try {
				checkAndLoadCpCertificates(claimsParty);
			} catch (TechnicalException ex) {
				log.error("Invalid CP={}: {}", claimsParty.getId(), ex.getInternalMessage());
				claimsParty.invalidate(ex);
			}
		}
	}

	public void validateScripts(ClaimsProviderSetup claimsProviderSetup) {
		for (ClaimsParty claimsParty : claimsProviderSetup.getClaimsParties()) {
			RelyingPartySetupUtil.validateScripts(claimsParty, scriptService);
		}
	}

	private void checkAndLoadCpCertificates(ClaimsParty claimsParty) {
		if (claimsParty.getCertificates() == null) {
			return;
		}
		var signerTruststore = claimsParty.getCertificates().getSignerTruststore();
		var credentials = credentialService.checkAndLoadTrustCredential(signerTruststore, claimsParty.getId(), claimsParty.getSubPath());
		claimsParty.setCpTrustCredential(credentials);

		var encryptionKeystore = claimsParty.getCertificates().getEncryptionKeystore();
		if (encryptionKeystore != null) {
			var keystoreCredential = credentialService.checkAndLoadCert(encryptionKeystore, claimsParty.getId(), claimsParty.getSubPath());
			List<Credential> decryptionCredentials = new ArrayList<>();
			decryptionCredentials.add(keystoreCredential);
			claimsParty.setCpDecryptionCredentials(decryptionCredentials);
		}

		if (claimsParty.getCertificates().getArtifactResolutionKeystore() != null) {
			log.warn("cpIssuerId={} is using deprecated Certificates.ArtifactResolutionKeystore={}"
							+ " - change to BackendKTruststore",
					claimsParty.getId(), claimsParty.getCertificates().getArtifactResolutionKeystore().getCertPath());
		}
		if (claimsParty.getCertificates().getArtifactResolutionTruststore() != null) {
			log.warn("cpIssuerId={} is using deprecated Certificates.ArtifactResolutionTruststore={}"
							+ " - change to BackendKTruststore",
					claimsParty.getId(), claimsParty.getCertificates().getArtifactResolutionTruststore().getCertPath());
		}

		if (claimsParty.getCertificates().getBackendKeystore() != null) {
			var backendCredential = credentialService.checkAndLoadCert(claimsParty.getCertificates().getBackendKeystore(),
					claimsParty.getId(), claimsParty.getSubPath());
			claimsParty.setCpBackendClientCredential(backendCredential);
		}
		if (claimsParty.getCertificates().getBackendTruststore() != null) {
			var backendTrustCredentials = credentialService.checkAndLoadTrustCredential(claimsParty.getCertificates().getBackendTruststore(),
					claimsParty.getId(), claimsParty.getSubPath());
			claimsParty.setCpBackendTrustCredentials(backendTrustCredentials);
		}

		if (claimsParty.getOidc() != null) {
			oidcEncryptionKeystoreService.loadClientsDecryptionKeystore(claimsParty.getId(), claimsParty.getSubPath(), claimsParty.getOidc().getClients());
		}

	}

	public void checkAndLoadRelyingPartyCertificates(RelyingPartySetup relyingParties) {
		for (RelyingParty relyingParty : relyingParties.getRelyingParties()) {
			try {
				checkAndLoadRelyingPartyCertificates(relyingParty);
			} catch (TechnicalException ex) {
				log.error("Invalid RelyingParty={}: {}", relyingParty.getId(), ex.getInternalMessage());
				relyingParty.invalidate(ex);
			} catch (Exception ex) {
				log.error("Invalid RelyingParty={}: {}", relyingParty.getId(), ex.getMessage());
				relyingParty.invalidate(ex);
			}
		}
	}

	private List<Credential> getSelfCert() {
		var selfSigner = trustBrokerProperties.getSigner();
		checkCertPath(selfSigner.getSignerCert(), "trustbroker.config.signer");
		return CredentialReader.readTrustCredentials(selfSigner.getSignerCert(), selfSigner.getType(),
				selfSigner.getPassword(), selfSigner.getKeyEntryId());
	}

	private void checkAndLoadRelyingPartyCertificates(RelyingParty relyingParty) {
		var rpCerts = relyingParty.getCertificates();
		if (rpCerts == null) {
			log.warn("RP={} has no certificate", relyingParty.getId());
			return;
		}

		var credential = credentialService.checkAndLoadCert(rpCerts.getSignerKeystore(), relyingParty.getId(), relyingParty.getSubPath());
		relyingParty.setRpSigner(credential);
		loadSloSignerCertificates(relyingParty);

		var credentials = credentialService.checkAndLoadTrustCredential(rpCerts.getSignerTruststore(), relyingParty.getId(),
				relyingParty.getSubPath());
		if (!relyingParty.getOidcClients().isEmpty()) {
			var selfSigner = trustBrokerProperties.getSigner();
			var selfCert = getSelfCert();
			credentials.addAll(selfCert);
			log.debug("rpId={} has OIDC configured, add own signer={} to truststore", relyingParty.getId(),
					selfSigner.getSignerCert());
		}
		relyingParty.setRpTrustCredentials(credentials);

		var encryptionTruststore = rpCerts.getEncryptionTruststore();
		if (encryptionTruststore != null) {
			var truststoreCredentials =
					credentialService.checkAndLoadTrustCredential(encryptionTruststore, relyingParty.getId(), relyingParty.getSubPath());
			if (!truststoreCredentials.isEmpty()) {
				if (truststoreCredentials.size() > 1) {
					log.info("EncryptionTruststore has multiple certs for rpIssuerId={}. Picking first one.",
							relyingParty.getId());
				}
				relyingParty.setRpEncryptionTrustCredential(truststoreCredentials.get(0));
			}
		}

		var encryptionKeystore = relyingParty.getCertificates().getEncryptionKeystore();
		if (encryptionKeystore != null) {
			var keystoreCredential = credentialService.checkAndLoadCert(encryptionKeystore, relyingParty.getId(), relyingParty.getSubPath());
			List<Credential> decryptionCredentials = new ArrayList<>();
			decryptionCredentials.add(keystoreCredential);
			relyingParty.setRpDecryptionCredentials(decryptionCredentials);
		}

		loadOidcEncKeystores(relyingParty);
	}

	private void loadOidcEncKeystores(RelyingParty relyingParty) {
		List<OidcClient> oidcClients = relyingParty.getOidcClients();
		if (oidcClients != null && !oidcClients.isEmpty()) {
			oidcEncryptionKeystoreService.loadClientsEncKeystore(relyingParty.getId(), relyingParty.getSubPath(), oidcClients);
		}
	}

	private void loadSloSignerCertificates(RelyingParty relyingParty) {
		if (relyingParty.getSso() != null) {
			for (var sloConfig : relyingParty.getSso().getSloResponse()) {
				var sloSignerKeystore = sloConfig.getSignerKeystore();
				if (sloSignerKeystore != null) {
					var sloCredential = credentialService.checkAndLoadCert(sloSignerKeystore, relyingParty.getId(), relyingParty.getSubPath());
					sloConfig.setSloSigner(sloCredential);
				}
			}
		}
	}

	private static void checkCertPath(String path, String urn) {
		if (StringUtils.isBlank(path)) {
			throw new TechnicalException(String.format("Certificate password is missing for urn=%s", urn));
		}
	}

	private int mustUpdateFiles() {
		var configurationPath = trustBrokerProperties.getConfigurationPath();
		var newConfigDir = getConfigCachePath(configurationPath) + BootstrapProperties.getSpringProfileActive() + "/";
		var newFiles = getAllFileNamesFromDir(newConfigDir);
		var oldFilesDir = configurationPath + GitService.CONFIGURATION_PATH_SUB_DIR_LATEST;
		var oldFiles = getAllFileNamesFromDir(oldFilesDir);

		if (newFiles.isEmpty() || oldFiles.isEmpty()) {
			throw new TechnicalException(String.format(
					"Could not read configuration files from activeConfigDir=%s or checkoutConfigDir=%s",
					oldFilesDir, newConfigDir));
		}
		if (newFiles.size() != oldFiles.size()) {
			log.info("Detected configuration change on activeConfigDir={} activeCount={} checkoutConfigDir={} checkoutCount={}",
					oldFilesDir, oldFiles.size(), newConfigDir, newFiles.size());
		}

		// check changed and removed files
		var fileChecked = 0;
		var fileChanged = 0;
		for (var oldFileName : oldFiles) {
			fileChecked += 1;
			var newFile = mapOldFileNameToNewFileName(oldFileName, oldFilesDir, newConfigDir);
			if (newFile == null) {
				log.info("Detected configuration remove of activeConfigFile={} fileCnt={}/{}",
						oldFileName, fileChecked, oldFiles.size());
				fileChanged += 1;
				continue;
			}
			try {
				var fileContentEqual = FileUtils.contentEquals(new File(oldFileName), newFile);
				if (!fileContentEqual) {
					log.info("Detected configuration diff on activeConfigFile={} checkoutConfigFile={} fileCnt={}/{}",
							oldFileName, newFile, fileChecked, oldFiles.size());
					fileChanged += 1;
				}
				newFiles.remove(newFile.getPath());
			} catch (IOException e) {
				throw new TechnicalException(String.format(
						"Could not compare config activeConfigFile=%s with checkoutConfigFile=%s fileCnt=%s/%s",
						oldFileName, newFile, fileChecked, oldFiles.size()), e);
			}
		}

		// check added files
		for (var newFileName : newFiles) {
			fileChecked += 1;
			fileChanged += 1;
			log.info("Detected configuration add of checkoutConfigFile={} fileCnt={}/{}",
					newFileName, fileChecked, oldFiles.size() + newFiles.size());
		}

		return fileChanged;
	}

	private static List<String> getAllFileNamesFromDir(String newFilesDir) {
		try (Stream<Path> walk = Files.walk(Paths.get(newFilesDir))) {
			var immutableList = walk.filter(Files::isRegularFile)
					.map(Path::toString)
					.toList();
			return new ArrayList<>(immutableList); // we need it mutable
		} catch (IOException e) {
			throw new TechnicalException(String.format("Could not read config files from dir=%s", newFilesDir), e);
		}
	}

	private static File mapOldFileNameToNewFileName(String oldFileName, String oldFilesDir, String newConfigDir) {
		var newFileName = oldFileName.replace(oldFilesDir, newConfigDir);
		var newFile = new File(newFileName);
		if (!newFile.exists()) {
			return null;
		}
		return newFile;
	}

	public void filterInvalidRelyingParties(RelyingPartySetup relyingPartySetup) {
		// remove invalid RPs
		var validRps = relyingPartySetup.getRelyingParties().stream()
				.filter(RelyingParty::isValid).toList();
		if (validRps.size() != relyingPartySetup.getRelyingParties().size()) {
			log.error("Ignoring ignoreCount={} invalid RelyingParties",
					relyingPartySetup.getRelyingParties().size() - validRps.size());
			relyingPartySetup.setUnfilteredRelyingParties(relyingPartySetup.getRelyingParties());
			relyingPartySetup.setRelyingParties(validRps);
		}
	}

	public void filterInvalidClaimsParties(ClaimsProviderSetup claimsProviderSetup) {
		// remove invalid CPs
		var validCps = claimsProviderSetup.getClaimsParties().stream()
				.filter(ClaimsParty::isValid).toList();
		if (validCps.size() != claimsProviderSetup.getClaimsParties().size()) {
			log.error("Ignoring ignoreCount={} invalid ClaimsParties",
					claimsProviderSetup.getClaimsParties().size() - validCps.size());
			claimsProviderSetup.setUnfilteredClaimsParties(claimsProviderSetup.getClaimsParties());
			claimsProviderSetup.setClaimsParties(validCps);
		}
	}
}
