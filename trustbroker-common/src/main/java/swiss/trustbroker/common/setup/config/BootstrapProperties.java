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

package swiss.trustbroker.common.setup.config;

import java.io.File;

import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.common.exception.TechnicalException;

@Slf4j
public class BootstrapProperties {

	// use workspace and use its structure by contract
	public static final String TRUSTBROKER_HOME = "TRUSTBROKER_HOME";

	// bootstrap from....
	public static final String GIT_REPO_URL = "GIT_URL";

	public static final String GIT_REPO_TOKEN = "GIT_TOKEN";

	// ...authenticating with...
	public static final String GIT_SSH_KEY_PATH = "CONFIG_KEY"; // path to SSH key file in TRUSTBROKER_HOME/keys/git-ssh.key

	// ...fetching branch...
	public static final String GIT_CONFIG_BRANCH = "CONFIG_BRANCH"; // master

	// ...caching locally in TRUSTBROKER_HOME/configuration
	public static final String GIT_CONFIG_CACHE = "CONFIG_PATH";

	private static final String GIT_KEY_PASSPHRASE = "GIT_KEY_PASSPHRASE";

	public static final String SSH_PROXY_HOST = "ssh.proxy.host"; // SSH_PROXY_HOST via env as well

	public static final String SSH_PROXY_PORT= "ssh.proxy.port";  // SSH_PROXY_PORT via env as well

	private BootstrapProperties() {}

	public static String getFromSysPropsOrEnv(String name, String defaultValue, boolean required) {
		String ret = System.getProperty(name);
		if (ret == null) {
			ret = System.getenv(name); // as is, but . are illegal
		}
		if (ret == null) {
			ret = System.getenv(name.replace(".", "_")); // better
		}
		if (ret == null) {
			ret = System.getenv(name.toUpperCase().replace(".", "_")); // ENV convention
		}
		if (ret == null) {
			ret = defaultValue;
		}
		if (ret == null && required) {
			String msg = String.format("No bootstrap variable '%s' found and no default can be derived", name);
			throw new TechnicalException(msg);
		}
		return ret;
	}

	public static String getWorkDirDefault() {
		return getWorkDirDefault(null);
	}

	public static String getWorkDirDefault(String subPath) {
		var workDir = getFromSysPropsOrEnv(TRUSTBROKER_HOME, "/etc/trustbroker", true);
		return subPath != null ? new File(workDir, subPath).getAbsolutePath() : new File(workDir).getAbsolutePath() ;
	}

	public static String getGitToken() {
		// defaults: supported by jgit ssh: id_rsa, id_ecdsa, id_ed25519
		return getGitToken(getWorkDirDefault("keys/git_token"));
	}

	public static String getGitToken(String defaultValue) {
		return getFromSysPropsOrEnv(GIT_REPO_TOKEN, defaultValue, true);
	}

	public static String getGitSshKeyPath() {
		// defaults: supported by jgit ssh: $HOME/.ssh/id_rsa + id_ecdsa + id_ed25519
		var userHome = System.getProperty("user.home");
		var defaultKey = userHome + "/" + SshTransportConfig.SSH_DIR + "/id_rsa";
		var idRsaFilePath = getFromSysPropsOrEnv(GIT_SSH_KEY_PATH, defaultKey, true);
		var idRsaFile = new File(idRsaFilePath);
		if (idRsaFile.exists()) {
			return idRsaFile.getAbsolutePath();
		}
		// fallback to $TRUSTBROKER_HOME/keys (jgit/2.4 legacy) for backward compatibility
		var idRsaFile2  = new File(getWorkDirDefault("keys/id_rsa"));
		if (idRsaFile2.exists()) {
			return idRsaFile2.getAbsolutePath();
		}
		// use preferred default if no id_rsa was located
		return idRsaFile.getAbsolutePath();
	}

	public static String getGitConfigCache() {
		var defaultValue = getWorkDirDefault("configuration");
		var ret = getFromSysPropsOrEnv(GIT_CONFIG_CACHE, defaultValue, true);
		// propagate to sysprops for backward compatibility (we have configs using ${CONFIG_PATH} still
		System.setProperty(GIT_CONFIG_CACHE, ret);
		return ret;
	}

	// we deliver a minimal application.yml with the application jar, profiles are downloaded from git
	public static String getSpringConfigLocation() {
		return "optional:classpath:/,file:" + getSpringConfigPath();
	}

	public static String getSpringConfigPath() {
		File latestConfig = new File(getGitConfigCache(), "latest/config/");
		return latestConfig.getAbsolutePath() + "/"; // it's a directory, so trailing / required
	}

	public static String getKeystorePath() {
		File latestConfig = new File(getGitConfigCache(), "latest/keystore/");
		return latestConfig.getAbsolutePath() + "/"; // it's a directory, so trailing / required
	}

	public static String getGitConfigBranch() {
		return getFromSysPropsOrEnv(GIT_CONFIG_BRANCH, "master", true);
	}

	public static String getGitRepoUrl() {
		return getFromSysPropsOrEnv(GIT_REPO_URL, null, true);
	}

	// get at least one profile as the trustbroker's default application.yaml is not sufficient to run the service
	public static String getSpringProfileActive() {
		String ret = getFromSysPropsOrEnv("spring.profiles.active", null, false);
		if (ret == null) {
			ret = getFromSysPropsOrEnv("SPRING_PROFILES_ACTIVE", "local", true);
			log.info("Bootstrap spring.profiles.active detection result: {}", ret);
		}
		return ret;
	}

	public static void validateBootstrap() {
		File checkFile = new File(getSpringConfigPath(), "application.yml");
		if (!checkFile.exists()) {
			String msg = String.format("Check TRUSTBROKER_HOME=%s and SPRING_PROFILE_ACTIVE=%s resulting in spring config %s"
							+ " populated with the checkout from %s (which seems to be missing or has an unexpected structure",
					System.getenv(TRUSTBROKER_HOME),
					BootstrapProperties.getSpringProfileActive(),
					checkFile.getAbsolutePath(),
					getGitRepoUrl());
			throw new TechnicalException(msg);
		}
	}

	public static String getPassphrase() {
		String passphrase = getFromSysPropsOrEnv(GIT_KEY_PASSPHRASE, null, false);
		if (passphrase == null) {
			log.debug("No passphrase was provided for SSH_KEY via ENV or system properties, assuming un-encrypted key");
		}
		return passphrase;
	}

	public static boolean isSshProxyDefined() {
		return getSshProxyHost() != null && getSshProxyPort() != null;
	}

	public static String getSshProxyHost() {
		return getFromSysPropsOrEnv(SSH_PROXY_HOST, null, false);
	}

	public static String getSshProxyPort() {
		return getFromSysPropsOrEnv(SSH_PROXY_PORT, null, false);
	}

}
