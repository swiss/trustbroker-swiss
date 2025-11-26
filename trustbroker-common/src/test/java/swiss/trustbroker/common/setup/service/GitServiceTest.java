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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.inOrder;

import java.io.File;
import java.io.IOException;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.setup.config.BootstrapProperties;
import swiss.trustbroker.common.setup.config.SshTransportConfig;
import swiss.trustbroker.common.util.DirectoryUtil;
import swiss.trustbroker.test.util.MemoryAppender;

@SpringBootTest
@ContextConfiguration(classes = { GitService.class })
class GitServiceTest {

	private static final org.slf4j.Logger log = LoggerFactory.getLogger(GitServiceTest.class);

	@Autowired
	GitService gitService;

	@MockitoBean
	DirectoryUtil directoryUtil;

	private MemoryAppender memoryAppender;

	private static final String CONFIG_PATH = "/configuration";

	private static final String GIT_URL = "ssh://git@git.test.swiss:7999/org/xtb-devops-demo.git2";

	private static final String GIT_BRANCH = "dummyBranch";

	@BeforeEach
	void setup() {
		Logger logger = (Logger) LoggerFactory.getLogger(GitService.class.getName());
		memoryAppender = new MemoryAppender();
		memoryAppender.setContext((LoggerContext) LoggerFactory.getILoggerFactory());
		logger.setLevel(Level.DEBUG);
		logger.addAppender(memoryAppender);
		memoryAppender.start();
	}

	@AfterEach
	void cleanUp() {
		memoryAppender.reset();
		memoryAppender.stop();
	}

	@Test
	void testSshBootstrap() throws IOException {
		System.setProperty("user.home", new File("./build/").getCanonicalPath()); // writeable, on K8S HOME might be / or null
		var expectedSshDir = new File("build/.ssh");
		var expectedConfig = new File(expectedSshDir, SshTransportConfig.SSH_CONFIG);
		if (expectedConfig.exists()) {
			assertTrue(expectedConfig.delete(), "Unable to delete " + expectedConfig.getAbsolutePath());
		}
		if (expectedSshDir.exists()) {
			assertTrue(expectedSshDir.delete(), "Unable to delete " + expectedSshDir.getAbsolutePath());
		}
		SshTransportConfig.checkJgitSetup();
		var sshTransport = new SshTransportConfig("/invalid/home/.ssh/id_rsa");
		assertThat(sshTransport.getSshConfig().getAbsolutePath(), is(expectedConfig.getAbsolutePath()));
		assertTrue(expectedSshDir.exists(), "Not found expected bootstrap config at " + expectedConfig.getAbsolutePath());
		assertTrue(expectedConfig.delete(), "Unable to delete " + expectedConfig.getAbsolutePath());
		assertTrue(expectedSshDir.delete(), "Unable to delete " + expectedSshDir.getAbsolutePath());
	}

	@Test
	void pullConfigChangesFailsTest() {
		var cache = new File(BootstrapProperties.getGitConfigCache());
		if (cache.exists()) {
			// Given a populated TRUSTBROKER_HOME this test fails because pull works and no exception is thrown
			// Workaround: Move away $HOME/trustbroker or $TRUSTBROKER_HOME or set HOME=/tmp
			log.info("Skipped pullConfigChangesFailsTest because it might succeed accidentally");
			return;
		}
		assertThrows(TechnicalException.class, () -> {
			gitService.pullConfiguration();
		});
	}

	@Test
	void configCheckAndSetupFailsTest() {
		var git = new GitService(directoryUtil);
		// trailing separator is needed because the service removes everything after the last separator
		assertThrows(TechnicalException.class, () ->
			git.configCheckAndSetup(CONFIG_PATH + "/", GIT_URL, GIT_BRANCH)
		);
		assertTrue(memoryAppender.contains("try #1", Level.WARN));
		// try #2 is only logged when clone was already there which actually never happens

		var inOrder = inOrder(directoryUtil);
		// try #1
		verifyBackupRestore(inOrder);
		// try #2
		verifyBackupRestore(inOrder);
	}

	private void verifyBackupRestore(InOrder inOrder) {
		inOrder.verify(directoryUtil).backupDirectory(CONFIG_PATH + GitService.CONFIG_CACHE_PATH,
				CONFIG_PATH + GitService.CONFIG_CACHE_BACKUP_PATH);
		inOrder.verify(directoryUtil).restoreBackup(CONFIG_PATH + GitService.CONFIG_CACHE_PATH,
				CONFIG_PATH + GitService.CONFIG_CACHE_BACKUP_PATH);
	}
}
