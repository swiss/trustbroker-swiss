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
import java.time.OffsetDateTime;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import swiss.trustbroker.common.setup.config.BootstrapProperties;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.config.dto.AdminAction;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.util.ApiSupport;

@Controller
@RequiredArgsConstructor
@Slf4j
public class PropertyConfigScheduler {

	private static final long MIN_RELOAD_DELAY = 1000L;

	private final AppConfigService appConfigService;

	private final GitService gitService;

	private final TrustBrokerProperties properties;

	private final GlobalExceptionHandler globalExceptionHandler;

	private long lastCall = 0L;

	// Config reload from git
	@Scheduled(cron = "${trustbroker.config.claimsMapping.syncSchedule}")
	public synchronized void run() {
		try {
			runSynchronization();
		}
		catch (Exception ex) {
			globalExceptionHandler.logException(ex);
		}
	}

	/**
	 * Allow a config reload every 1sec (a bit of DOS prevention) given the client knows the admin secret.
	 * Returns HTTP/404 when the feature is disabled (default) or the action or secret is wrong.
	 * Copy & paste this one in DEV "local" setup to speed up config changes.<pre>
	 * curl -kv http://localhost:8090/api/v1/config \
	 *   -H 'Content-Type: application/json' \
	 *   -d '{"action":"reload","adminSecret":"trustbroker.config.adminSecret"}'
	 * </pre>
	 */
	@PostMapping(path = ApiSupport.RECONFIG_URL, consumes = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<String> checkReconfig(@RequestBody AdminAction action) {
		try {
			var adminSecret = properties.getAdminSecret();
			if (adminSecret != null && action != null
					&& "reload".equals(action.getAction())
					&& adminSecret.equals(action.getAdminSecret())) {
				waitToReduceDos();
				var result = runSynchronization();
				return ResponseEntity.ok().body(OffsetDateTime.now() + " " + result + "\n"); // HTTP/200 Done
			}
		}
		catch (Exception ex) {
			globalExceptionHandler.logException(ex);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build(); // HTTP/500 Error
		}
		return ResponseEntity.status(HttpStatus.NOT_FOUND).build(); // HTTP/404 Not Found (for caller)
	}

	public synchronized String runSynchronization() {
		lastCall = System.currentTimeMillis();

		var remoteHasChanges = gitService.remoteHasChanges();
		if (!remoteHasChanges) {
			log.info("No changes on configuration repo={} branch={}", GitService.getGitUrl(), GitService.getGitBranch());
			return "0 changes";
		}

		var vetoFile = new File(BootstrapProperties.getGitConfigCache(), "veto");
		if (vetoFile.exists()) {
			log.info("Veto on local configuration by vetoFile={}", vetoFile.getAbsolutePath());
			return "veto active";
		}

		log.debug("Checking configuration in stage={} from repo={} branch={}...",
				BootstrapProperties.getSpringProfileActive(), GitService.getGitUrl(), GitService.getGitBranch());

		var start = System.currentTimeMillis();
		var configCache = GitService.getConfigCachePath();
		var cacheDir = new File(configCache);
		if (cacheDir.exists() && cacheDir.isDirectory()) {
			gitService.pullConfiguration();
		}
		else {
			gitService.cloneConfiguration();
		}

		var changed = appConfigService.checkAndUpdate();
		var dtms = System.currentTimeMillis() - start;
		log.info("Configuration in stage={} from repo={} branch={} checked in dTms={} having ChangeCount={} changes",
				BootstrapProperties.getSpringProfileActive(), GitService.getGitUrl(), GitService.getGitBranch(), dtms, changed);

		lastCall = System.currentTimeMillis();
		return changed + " changes applied";
	}

	private synchronized long computeDelay() {
		return Math.min(MIN_RELOAD_DELAY - (System.currentTimeMillis() - lastCall),  MIN_RELOAD_DELAY);
	}

	// protect git repo from DOS calls
	private synchronized void waitToReduceDos() {
		var delay = computeDelay();
		while (delay > 0) {
			try {
				log.debug("DOS prevention on GIT repo delaing={} msec", delay);
				wait(delay);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			delay = computeDelay();
		}
	}

}
