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

package swiss.trustbroker.common.setup.service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.List;

import io.micrometer.core.annotation.Timed;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.TransportConfigCallback;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.lib.Ref;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.setup.config.BootstrapProperties;
import swiss.trustbroker.common.setup.config.HttpTransportConfig;
import swiss.trustbroker.common.setup.config.SshTransportConfig;
import swiss.trustbroker.common.tracing.Traced;
import swiss.trustbroker.common.util.DirectoryUtil;

@SuppressWarnings("java:S1075") // our config structure is defined, no need for configuration
@Slf4j
public class GitService {

	public static final String CONFIGURATION_PATH_SUB_DIR_LATEST = "/latest/";

	private static final String CONFIGURATION_PATH_SUB_DIR_NEW = "/new/";

	private static final String CONFIGURATION_PATH_SUB_DIR_PREVIOUS = "/previous/";

	private static final String CONFIGURATION_PATH_SUB_DIR_OLDEST = "/old/";

	static final String CONFIG_CACHE_PATH = "/configCache/";

	static final String CONFIG_CACHE_BACKUP_PATH = "/configCache.bak";

	private static final String TRUSTBROKER_INVENTORIES = "/trustbroker-inventories/";

	private static final String LAST_COMMIT_ID = "LastCommitId";

	private static final String GIT_CONNECT_HINT
			= " (HINT: In case of authorization failures check SSH_KEY (HOME/.ssh/id_rsa) or GIT_TOKEN (HOME/keys/git_token))";

	private final DirectoryUtil directoryUtil;

	public GitService(DirectoryUtil directoryUtil) {
		this.directoryUtil = directoryUtil;
		this.refresh(); // apply logging for boostrap too
	}

	// re-apply in case log level changes for git sub-system were applied
	public void refresh() {
		log.debug("No changes necessary on GitService");
	}

	public static String getGitUrl() {
		return BootstrapProperties.getGitRepoUrl();
	}

	public static String getGitBranch() {
		return BootstrapProperties.getGitConfigBranch();
	}

	@Traced
	@Timed("git_fetch")
	public boolean remoteHasChanges() {
		if (hasRemoteConfigVeto()) {
			log.debug("Assume remote change, local changes are directly checked and consumed");
			return true;
		}
		// check remote for repo changes
		var gitRepoUrl = BootstrapProperties.getGitRepoUrl();
		var gitBranch = BootstrapProperties.getGitConfigBranch();
		var transportConfig = initTransportConfig(gitRepoUrl);
		return isNewCommitOnRemote(transportConfig, gitRepoUrl, gitBranch);
	}

	private static TransportConfigCallback initTransportConfig(String gitRepoUrl) {
		if (gitRepoUrl.startsWith("http")) {
			return new HttpTransportConfig(BootstrapProperties.getGitToken());
		}
		return new SshTransportConfig(BootstrapProperties.getGitSshKeyPath());
	}

	// Re-configuration is scheduled every 1min and retries are therefore done on a 1min base which is OK
	// The scheduler itself has a top-level catcher handling _all_ exceptions, so we do not differentiate here between
	// all the possible error cases JGit provides. We just make sure full context is on the exception message in the logs.
	@Traced
	@Timed("git_pull")
	public void pullConfiguration() {
		log.debug("Start GIT pull process");
		var configCache = getConfigCachePath();
		var workingDir = new File(configCache);
		var gitRepoUrl = getGitUrl();
		var gitRepoBranch = getGitBranch();
		var transportConfig = initTransportConfig(gitRepoUrl);
		try (var git = Git.open(workingDir)) {
			pullConfig(transportConfig, git);
			log.info("Pulled GIT changes successfully from repo={} branch={}", gitRepoUrl, gitRepoBranch);
		}
		catch (Exception e) {
			throw new TechnicalException(String.format("GIT pull on repo=%s branch=%s failed with error=%s: %s",
					getGitUrl(), getGitBranch(), e.getClass().getSimpleName(), e.getMessage()), e);
		}
	}

	private boolean isNewCommitOnRemote(TransportConfigCallback transportConfig, String gitRepoUrl, String gitBranch) {
		var remoteLastCommit = getRemoteLastCommit(transportConfig, gitRepoUrl, gitBranch);
		var commitId = getLastCommit();
		if (commitId == null || commitId.isEmpty()) {
			log.info("{} was not saved, running in veto mode", LAST_COMMIT_ID);
			return false;
		}
		var newCommit = !remoteLastCommit.equals(commitId);
		if (newCommit) {
			saveLastCommit(remoteLastCommit);
		}
		return newCommit;
	}

	private static void saveLastCommit(String remoteLastCommit) {
		System.setProperty(LAST_COMMIT_ID, remoteLastCommit);
	}

	private static String getLastCommit() {
		return System.getProperty(LAST_COMMIT_ID);
	}

	public static String getConfigCachePath() {
		var configurationPath = BootstrapProperties.getGitConfigCache();
		return getConfigCachePath(configurationPath);
	}

	private static String getConfigCachePath(String configurationPath) {
		return getConfigCachePath(configurationPath, CONFIG_CACHE_PATH);
	}

	private static String getConfigCacheBackupPath(String configurationPath) {
		return getConfigCachePath(configurationPath, CONFIG_CACHE_BACKUP_PATH);
	}

	private static String getConfigCachePath(String configurationPath, String dir) {
		if (configurationPath == null) {
			throw new TechnicalException("Missing GitConfigCache");
		}
		int last = configurationPath.lastIndexOf("/");
		return configurationPath.substring(0, last) + dir;
	}

	// This method is called at startup and on in K8S we never have an existing checkout as we do not use PVCs.
	// If Git is not available, the POD goes into CrashLoopBackOff retry loop, so we fix only a short temporary
	// problem here. K8S does the rest.
	public void configCheckAndSetup(String configurationPath, String gitUrl, String configBranch) {
		// pre-conditions
		if (StringUtils.isBlank(gitUrl) || StringUtils.isBlank(configurationPath)) {
			throw new TechnicalException("Missing git URL or config path, the application can not start");
		}

		// jsch has a pretty annoying default behaviour considering $HOME/.ssh leading to using wrong key
		if (gitUrl.contains("ssh")) {
			SshTransportConfig.checkJgitSetup();
		}

		// clone from remote into empty local (for dev we might already have a config, but not in PODs)
		try {
			manageStartUpConfig(gitUrl, configBranch, configurationPath);
		}
		catch (TechnicalException tex) {
			// assume that failing 2nd try will have the same root cause than the first try
			var rootCause = tex.getInternalMessage();
			// as we are resilient here with a second try, we only log as a warning for first try
			log.warn("GIT clone try #1 on repo='{}' branch='{}' failed with error='{}'", gitUrl, configBranch, rootCause);
			var newConfigurationPath = configurationPath + CONFIGURATION_PATH_SUB_DIR_NEW;
			directoryUtil.deleteDirectory(newConfigurationPath);
			try {
				manageStartUpConfig(gitUrl, configBranch, configurationPath);
			}
			catch (TechnicalException tex2) {
				rootCause = tex2.getInternalMessage();
				var latestConfigurationPath = configurationPath + CONFIGURATION_PATH_SUB_DIR_LATEST;
				if (!directoryUtil.directoryExists(latestConfigurationPath)) {
					throw new TechnicalException(String.format(
							"GIT clone try #2 on repo='%s' branch='%s' failed with error='%s' => missing latestConfig='%s'" +
							GIT_CONNECT_HINT, gitUrl, configBranch, rootCause, latestConfigurationPath), tex2);
				}
				else {
					// no updates hurt at some point too so make this an error
					log.error("GIT clone try #2 on repo='{}' branch='{}' failed with error='{}' => use latestConfig='{}'" +
							GIT_CONNECT_HINT, gitUrl, configBranch, rootCause, latestConfigurationPath, tex2);
				}
			}
		}
	}

	private static void pullConfig(TransportConfigCallback transportConfig, Git git) throws GitAPIException {
		var start = System.currentTimeMillis();
		var status = "NOK";
		try {
			gitPull(transportConfig, git);
			status = "OK";
		}
		finally {
			var dt = System.currentTimeMillis() - start;
			log.info("Pulled GIT repo={} in dTms={} result={}", getGitUrl(), dt, status);
		}
	}

	private static void gitPull(TransportConfigCallback transportConfig, Git git) throws GitAPIException {
		var pullCommand = git.pull();
		pullCommand.setTransportConfigCallback(transportConfig);
		pullCommand.setRemoteBranchName(BootstrapProperties.getGitConfigBranch());
		pullCommand.call();
	}

	@Timed("git_clone")
	public void cloneConfig(File workingDir, String gitRepoUrl, String configBranch)
			throws GitAPIException {
		var start = System.currentTimeMillis();
		var status = "NOK";
		try {
			var transportConfig = initTransportConfig(gitRepoUrl);
			gitClone(transportConfig, workingDir, gitRepoUrl, configBranch);
			status = "OK";
		}
		finally {
			var dt = System.currentTimeMillis() - start;
			log.info("Cloning GIT branch={} from gitUrl={} to workingDir={} in dTms={} result={}",
					configBranch, gitRepoUrl, workingDir.getAbsolutePath(), dt, status);
		}
	}

	private void gitClone(TransportConfigCallback transportConfig, File workingDir, String gitUrl, String configBranch)
			throws GitAPIException {
		validateRemoteGitBranch(transportConfig, gitUrl, configBranch);
		var cloneCommand = Git.cloneRepository();
		cloneCommand.setURI(gitUrl);
		cloneCommand.setTransportConfigCallback(transportConfig);
		cloneCommand.setBranch(configBranch);
		cloneCommand.setDirectory(workingDir);
		try (var git = cloneCommand.call()) {
			log.debug("Clone command done on {}", git);
		}
		saveCommitId(transportConfig, gitUrl, configBranch);
	}

	private void saveCommitId(TransportConfigCallback transportConfig, String gitUrl, String configBranch) {
		var remoteLastCommit = getRemoteLastCommit(transportConfig, gitUrl, configBranch);
		saveLastCommit(remoteLastCommit);
	}

	@Traced
	public String getRemoteLastCommit(TransportConfigCallback transportConfig, String gitUrl, String gitBranch) {
		Collection<Ref> refs;
		try {
			refs = Git.lsRemoteRepository()
					.setHeads(true)
					.setTags(true)
					.setRemote(gitUrl)
					.setTransportConfigCallback(transportConfig)
					.call();

			List<Ref> collect = refs.stream()
					.filter(ref1 -> ref1.getName().equals(Constants.R_HEADS + gitBranch))
					.toList();
			if (collect.isEmpty()) {
				throw new TechnicalException(String.format(
						"Failed to find GIT remote branch/tag using gitUrl=%s branch=%s (HINT: Check setup)",
						gitUrl, gitBranch));
			}
			if (collect.size() > 1) {
				log.error("{} commit error", gitBranch);
			}

			var ref = collect.get(0);
			if (ref != null) {
				var objectId = ref.getObjectId();
				if (objectId != null) {
					return objectId.getName();
				}
			}
		}
		catch (Exception e) {
			throw new TechnicalException(String.format(
					"GIT list on repo=%s branch=%s failed with error=%s: %s." + GIT_CONNECT_HINT,
					gitUrl, gitBranch, e.getClass().getSimpleName(), e.getMessage()), e);
		}

		// unlikely that we get here except as GIT should always have a commitId on everything
		throw new TechnicalException(String.format("Something went wrong extracting commitId from gitUrl=%s branch=%s",
				gitUrl, gitBranch));
	}

	// used by gitClone so we trace all remote calls there
	private static void validateRemoteGitBranch(TransportConfigCallback transportConfig, String gitUrl, String configBranch)
			throws GitAPIException {
		// Clone does not throw any exception, if the branch does not exist on the remote repository.
		Git.lsRemoteRepository()
				.setRemote(gitUrl)
				.setTransportConfigCallback(transportConfig)
				.setHeads(true)
				.call()
				.stream()
				.filter(ref -> ref.getName().endsWith("/" + configBranch))
				.findFirst()
				.ifPresentOrElse(ref -> log.info("GIT repo={} branch={} is valid", gitUrl, configBranch),
						() -> {
							var msg = String.format("GIT repo=%s branch=%s does not exist", gitUrl, configBranch);
							throw new TechnicalException(msg);
						});
	}

	public void manageStartUpConfig(String gitUrl, String configBranch,	String configurationPath) {
		log.debug("Start GIT clone process");
		var configCache = getConfigCachePath(configurationPath);
		var configCacheBak = getConfigCacheBackupPath(configurationPath);
		directoryUtil.backupDirectory(configCache, configCacheBak);
		try {
			cloneConfig(new File(configCache), gitUrl, configBranch);
		}
		catch (GitAPIException | RuntimeException ex) {
			directoryUtil.restoreBackup(configCache, configCacheBak);
			throw (ex instanceof TechnicalException tex ? tex :
					new TechnicalException(String.format("Cloning failed with rootCause='%s' from gitUrl=%s",
							ex.getMessage(), gitUrl), ex));
		}
		directoryUtil.deleteDirectory(configCacheBak);
		log.debug("Finished GIT clone process");
		rolloverConfig(configurationPath);
	}

	public void rolloverConfig(String configurationPath) {
		var start = System.currentTimeMillis();
		var status = "NOK";
		try {
			configRollover(configurationPath);
			status = "OK";
		}
		finally {
			var dt = System.currentTimeMillis() - start;
			log.info("Rollover configPath={} in dTms={} result={}", configurationPath, dt, status);
		}
	}

	private void configRollover(String configurationPath) {
		log.debug("Start directory rollover on configPath={}", configurationPath);
		// source references (into git configCache)
		var configCache = getConfigCachePath(configurationPath);
		var profileCache = configCache + TRUSTBROKER_INVENTORIES + BootstrapProperties.getSpringProfileActive();

		// copy checkout to new
		var configPathNew = configurationPath + CONFIGURATION_PATH_SUB_DIR_NEW;
		directoryUtil.copyDir(profileCache, configPathNew);

		// rollover i.e. rotate generations as follows: new (fetched) => latest (active) => previous (FY) => old (deleted)
		// NOTE: We delete twice because NFS storage might have delay deleting
		// target references (into configuration)
		var configPathOld = configurationPath + CONFIGURATION_PATH_SUB_DIR_OLDEST;
		var configPathPrevious = configurationPath + CONFIGURATION_PATH_SUB_DIR_PREVIOUS;
		var configPathLatest = configurationPath + CONFIGURATION_PATH_SUB_DIR_LATEST;
		directoryUtil.backupDirectory(configPathPrevious, configPathOld);
		directoryUtil.renameDirectory(configPathLatest, configPathPrevious);
		directoryUtil.renameDirectory(configPathNew, configPathLatest);
		directoryUtil.deleteDirectory(configPathOld); // do it this time (NFS handling might have delays)
		log.debug("Finished directory rollover on configPath={}", configurationPath);
	}


	public static void bootConfiguration() {
		var directoryUtil = new DirectoryUtil();
		var gitService = new GitService(directoryUtil);
		gitService.cloneConfiguration();
	}

	@Traced
	public void cloneConfiguration() {
		// MUST have: GIT to connect to and the branch to download
		var gitUrl = BootstrapProperties.getGitRepoUrl();
		var gitBranch = BootstrapProperties.getGitConfigBranch();

		// MUST have: Cache area where we download or mount our setup
		var configCachePath = BootstrapProperties.getGitConfigCache();
		log.info("Using configCachePath={} for gitBranch={} from gitUrl={}", configCachePath,gitBranch, gitUrl);

		// def support: adhoc disabling checkout to debug the config content
		if (hasRemoteConfigVeto()) {
			return;
		}

		// check credential boostrap
		checkCredentialBootstrap(gitUrl);

		// clone
		configCheckAndSetup(configCachePath, gitUrl, gitBranch);
	}

	private void checkCredentialBootstrap(String gitUrl) {
		if (gitUrl.startsWith("http")) {
			checkCredentialBootstrapHttp(gitUrl);
		}
		else {
			checkCredentialBootstrapSsh(gitUrl);
		}
	}

	private void checkCredentialBootstrapHttp(String gitUrl) {
		var token = BootstrapProperties.getGitToken();
		if (log.isDebugEnabled()) {
			if (token != null && new File(token).exists()) {
				log.debug("Using GIT token from file={} to access repo={}", token, gitUrl);
			}
			else {
				log.debug("Using GIT token={} to access repo={}", (token != null && token.length() > 6) ?
						token.substring(6) + "..." : token, gitUrl);
			}
		}
	}

	private void checkCredentialBootstrapSsh(String gitUrl) {
		// MUST have: SSH key to authenticate on gitUrl
		var gitKeyPath = BootstrapProperties.getGitSshKeyPath();
		var sshKeyFile = new File(gitKeyPath);
		// jgit/2.6 migration: We are using ssh client convention now
		if (!sshKeyFile.exists()) {
			var oldKeyFile = new File(BootstrapProperties.getWorkDirDefault("keys/git-ssh.key"));
			if (oldKeyFile.exists() && oldKeyFile.renameTo(sshKeyFile)) {
				log.info("Migrated oldKeyFile={} to sshKeyFile={}", oldKeyFile.getAbsoluteFile(), sshKeyFile.getAbsolutePath());
			}
		}
		if (!sshKeyFile.exists()) {
			var sshKey = System.getenv("SSH_KEY");
			if (sshKey == null || sshKey.isEmpty()) {
				log.warn("No SSH key found at {} or in SSH_KEY environment. Accessing {} anonymously.",
						sshKeyFile.getAbsolutePath(), gitUrl);
			}
			else {
				// cache the key (if then config map changes, the POD need a restart anyway)
				createKeyFile(sshKey, gitKeyPath);
			}
		}
		if (sshKeyFile.exists()) {
			log.debug("Using GIT key from {} to access {}", sshKeyFile.getAbsolutePath(), gitUrl);
		}
	}

	public boolean hasRemoteConfigVeto() {
		var vetoFile = new File(BootstrapProperties.getGitConfigCache(), "veto");
		if (vetoFile.exists()) {
			log.info("Remote config check/pull vetoed by {}", vetoFile.getAbsolutePath());
			return true;
		}
		return false;
	}

	// optional key caching from env
	private void createKeyFile(String sshKey, String gitKeyCachePath) {
		byte[] bytes = Base64.decodeBase64(sshKey);
		var file = new File(gitKeyCachePath);
		directoryUtil.createDirectoryIfNotExisting(file, "SSH_KEY");
		if (!file.exists()) {
			try (OutputStream stream = new FileOutputStream(file)) {
				stream.write(bytes);
			}
			catch (Exception e) {
				throw new TechnicalException(String.format("Could not cache SSH_KEY from env in file %s. Error Detail: %s",
						gitKeyCachePath, e.getMessage()), e);
			}
		}
	}

}
