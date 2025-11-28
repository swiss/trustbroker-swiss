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
import java.io.IOException;
import java.nio.file.Files;

import lombok.extern.slf4j.Slf4j;
import org.eclipse.jgit.api.TransportConfigCallback;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.transport.SshConstants;
import org.eclipse.jgit.transport.SshSessionFactory;
import org.eclipse.jgit.transport.SshTransport;
import org.eclipse.jgit.transport.Transport;
import org.eclipse.jgit.transport.sshd.SshdSessionFactoryBuilder;
import swiss.trustbroker.common.exception.TechnicalException;

@Slf4j
public class SshTransportConfig implements TransportConfigCallback {

	public static final String SSH_DIR = SshConstants.SSH_DIR; // .ssh

	public static final String SSH_CONFIG = Constants.CONFIG; // config

	private final File sshDir; // directory where id_rsa resided, default BootstrapProperties.getGitSshKeyPath()

	private final File sshConfig; // required to locate config and/or known_hosts to skip or verify git server public keys

	public SshTransportConfig(String sshKey) {
		var keyFile = new File(sshKey);
		var keyDir = keyFile.getParentFile();
		var userDir = getUserHome();
		this.sshDir = keyDir.canWrite() ? keyDir : new File(userDir, SSH_DIR);
		this.sshConfig = new File(sshDir, SSH_CONFIG);
		checkAndBootstrapSshConfig();
		log.info("Accessing git with sshKey='{}' and sshConfig='{}' {}",
				keyFile.getAbsolutePath(), this.sshConfig,
				keyFile.exists() ? "" : "(WARN: Key file does not exist, check SSH setup, other key files might apply)");
	}

	private void checkAndBootstrapSshConfig() {
		if (!sshDir.exists() && sshDir.getParentFile().canWrite() && sshDir.mkdir()) {
			log.info("Bootstrapped SSH setup at {}", sshDir.getAbsolutePath());
		}
		if (!sshConfig.exists() && bootstrapSshConfig(sshConfig)) {
			log.info("Bootstrapped SSH config at {}", sshConfig.getAbsolutePath());
		}
	}

	private boolean bootstrapSshConfig(File sshConfig) {
		try {
			log.info("Enable bootstrapping git server by setting StrictHostKeyChecking=no (map {} and "
					+ "known_hosts to do a pre-defined secure bootstrap)", sshConfig.getAbsolutePath());
			if (sshConfig.createNewFile()) {
				Files.writeString(sshConfig.toPath(), "Host *\n  StrictHostKeyChecking no\n");
				return true;
			}
			else {
				log.warn("Failed creating sshConfig={}, trying with known_hosts trust", sshConfig.getAbsolutePath());
				return false;
			}
		}
		catch (IOException e) {
			throw new TechnicalException(String.format("Cannot disable host checking in %s (%s)",
					sshConfig.getParentFile().getAbsolutePath(), e.getMessage()), e);
		}
	}

	private SshSessionFactory buildSshSessionFactory() {
		var homeDir = new File(BootstrapProperties.getWorkDirDefault());
		var builder = new SshdSessionFactoryBuilder();
		var customProxyDataFactory = new CustomProxyDataFactory();
		return builder
				.withDefaultConnectorFactory()
				.setHomeDirectory(homeDir)
				.setSshDirectory(sshDir)
				.setConfigFile(file -> sshConfig)
				.setProxyDataFactory(BootstrapProperties.isSshProxyDefined() ? customProxyDataFactory : null)
				.setKeyPasswordProvider(SshKeyPasswordProvider::new)
				.build(null);
	}



	@Override
	public void configure(Transport transport) {
		if (transport instanceof SshTransport sshTransport) {
			sshTransport.setSshSessionFactory(buildSshSessionFactory());
		}
	}

	public File getSshConfig() {
		return sshConfig;
	}

	private static File getUserHome() {
		var javaHomeProperty = "user.home";
		var home = System.getProperty(javaHomeProperty);
		if (home == null) {
			home = "/etc/trustbroker";
			log.warn("No {} defined, setting it to {}", javaHomeProperty, home);
			System.setProperty(javaHomeProperty, home);
		}
		return new File(home);
	}

	// startup check
	public static void checkJgitSetup() {
		// jgit uses ~/.ssh/config per default to setup the client and ~/ssh/known_hosts to verify server keys
		var userHome = getUserHome(); // depends on runtime (/home/user or /etc/trustbroker or /)
		var userSsh = new File(userHome, SshTransportConfig.SSH_DIR); // jgit default
		if (!userHome.exists()) {
			log.error("Invalid user.home={} might lead to problems locating .ssh/config and .ssh/known_hosts",
					userSsh.getAbsolutePath());
		}
		else if (!userSsh.exists() && !userHome.canWrite()) {
			log.warn("Missing {} might lead to problems locating config and/or known_hosts to validate trusted servers",
					userSsh.getAbsolutePath());
		}
		else if (userSsh.getAbsolutePath().startsWith("/home")) {
			log.info("Real user.home ssh setup at {} used for config and known_host checks",
					userSsh.getAbsolutePath());
		}
	}

}
