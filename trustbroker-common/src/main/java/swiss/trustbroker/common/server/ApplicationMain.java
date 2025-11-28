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

package swiss.trustbroker.common.server;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.LoggerFactory;
import swiss.trustbroker.common.exception.TrustBrokerException;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.setup.config.BootstrapProperties;
import swiss.trustbroker.common.setup.service.GitService;

/**
 * Initialize everything before starting spring container, especially libraries using statics.
 */
@Slf4j
public class ApplicationMain {

	private static final String HTTPS_PROXY_SYS = "https_proxy";

	private static final String HTTPS_PROXY_HOST = "https.proxyHost";

	private static final String HTTPS_PROXY_PORT = "https.proxyPort";

	private ApplicationMain() {}

	// using backends with un-official CAs we need custom engineered tls-truststore.p12 etc.
	private static void checkTlsSetup() {
		String trustStore = System.getProperty("javax.net.ssl.trustStore");
		if (trustStore != null) {
			File trustStoreFile = new File(System.getProperty("javax.net.ssl.trustStore"));
			if (!trustStoreFile.exists()) {
				throw new IllegalArgumentException("TLS setup broken, check " + trustStoreFile.getAbsolutePath());
			}
			log.info("TLS setup: Running with trustStore={} in javaHome={}",
					trustStoreFile.getAbsolutePath(), System.getProperty("java.home"));
		}
		else {
			log.info("TLS setup: Running with JDK/JRE cacerts from javaHome={}", System.getProperty("java.home"));
		}
	}

	// allow injecting http proxy from system ENV so we do not need to patch VM args into the startup command
	private static void checkAndSetProxy() {
		var proxyEnv = BootstrapProperties.getFromSysPropsOrEnv(HTTPS_PROXY_SYS, null, false);
		var proxyVm = System.getProperty(HTTPS_PROXY_HOST);
		if (!StringUtils.isEmpty(proxyEnv) && StringUtils.isEmpty(proxyVm)) {
			try {
				var proxyUri = new URI(proxyEnv);
				System.setProperty(HTTPS_PROXY_HOST, proxyUri.getHost());
				System.setProperty(HTTPS_PROXY_PORT, Integer.toString(proxyUri.getPort()));
			}
			catch (URISyntaxException e) {
				log.warn("Ignoring system https_proxy={}: {}", proxyEnv, e.getMessage());
			}
		}
		var proxyHost = System.getProperty(HTTPS_PROXY_HOST);
		var proxyPort = System.getProperty(HTTPS_PROXY_PORT);
		if (proxyHost != null) {
			log.info("Proxy setup: Running HTTPS with proxyHost={} proxyPort={}", proxyHost, proxyPort);
		}
	}

	// get rid of DEBUG before spring-boot kicks in
	@SuppressWarnings("java:S4792") // injected boot log level from env or system properties, not user controlled
	public static void configureLogback() {
		// bootstrap defaults to DEBUG logging which is too much for us
		String bootLevel = BootstrapProperties.getFromSysPropsOrEnv("logging.level.root", "INFO", false);
		// assume SLF4J is bound to logback in the current environment
		LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
		loggerContext.getLogger("root").setLevel(Level.toLevel(bootLevel));
	}

	public static void configureHome() {
		var trustbrokerHome = BootstrapProperties.getWorkDirDefault();
		var userHome = System.getProperty("user.home");
		if (userHome == null || userHome.equals("/") || !userHome.equals(trustbrokerHome)) {
			// K8S we get no HOME or HOME=/, on a real system the id_rsa is usually not mounted and id_rsa is encrypted
			System.setProperty("user.home", trustbrokerHome);
			log.info("Setting user.home to {}={}", BootstrapProperties.TRUSTBROKER_HOME, trustbrokerHome);
		}
		else {
			log.info("Using user.home={} {}={}", userHome, BootstrapProperties.TRUSTBROKER_HOME, trustbrokerHome);
		}
	}

	// Support bootRun, IDE run etc
	// For our re-config support we always disable the automatic re-loading options to not spam the logs and remove overhead
	public static String[] getCompleteDefaultArgs(String[] args) {
		List<String> betterArgs = new ArrayList<>();
		Collections.addAll(betterArgs, args);
		// no args means DEV
		if (args.length == 0) {
			betterArgs.add("--spring.config.location=" + BootstrapProperties.getSpringConfigLocation());
			betterArgs.add("--spring.profiles.active=" + BootstrapProperties.getSpringProfileActive());
		}

		//  The spring.cloud stuff is required because of our re-config support only
		boolean skipSpringCloud = false;
		for (String arg : betterArgs) {
			if (arg.startsWith("--spring.cloud.bootstrap.enabled") || arg.startsWith("--spring.cloud.config.enabled")) {
				skipSpringCloud = true;
			}
		}
		if (!skipSpringCloud) {
			betterArgs.add("--spring.cloud.bootstrap.enabled=false");
			betterArgs.add("--spring.cloud.config.enabled=false");
		}

		// show what we use
		for (String arg : betterArgs) {
			log.info("Startup with arg: {}", arg);
		}
		return betterArgs.toArray(new String[0]);
	}

	private static void showJavaVersion() {
		log.info("Running JVM: {}", Runtime.version());
	}

	private static void showSecurityProviders() {
		log.info("Java security providers: count={}", Security.getProviders().length);
		for (var provider : Security.getProviders()) {
			log.info("* Java security provider name={} class={}", provider.getName(), provider.getClass().getName());
		}
	}

	protected static void initSamlSubSubsystem() {
		SamlInitializer.initSamlSubSystem();
	}

	// simple version, no IPs and other context
	protected static void logException(Throwable ex) {
		if (ex instanceof TrustBrokerException tex) {
			log.error(tex.getInternalMessage(), ex);
		}
		else if (ex.getCause() != null && ex.getCause() instanceof TrustBrokerException cex) {
			logException(cex); // handle exceptions in constructors, @PostConstruct etc unwrapped
		}
		else {
			log.error(ex.getMessage(), ex);
		}
	}

	// Application gets config from Git and runs a scheduler to keep it up-to-date
	@SuppressWarnings("java:S1147") // called from main, may System.exit
	public static void runBootstrap() {
		try {
			// logback bootstrap to not DEBUG
			configureLogback();

			// make sure user.home does not interfere for SSH access
			configureHome();

			// check JVM and its sub-system allowing connection to git repo
			showJavaVersion();
			checkAndSetProxy();

			// bootstrap config
			GitService.bootConfiguration();
			BootstrapProperties.validateBootstrap();
			checkTlsSetup();

			// security stuff
			initSamlSubSubsystem();
			showSecurityProviders();
		}
		catch (Exception e) {
			logException(e);
			System.exit(1);
		}
	}

}
