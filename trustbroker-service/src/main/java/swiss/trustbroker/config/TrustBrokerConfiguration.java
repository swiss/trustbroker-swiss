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

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import lombok.extern.slf4j.Slf4j;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.storage.StorageService;
import org.springframework.boot.web.embedded.tomcat.TomcatContextCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import swiss.trustbroker.common.saml.service.ArtifactCacheService;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.DirectoryUtil;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.sessioncache.repo.ArtifactCacheRepository;
import swiss.trustbroker.sessioncache.service.ArtifactStorageService;

@Configuration
@Slf4j
public class TrustBrokerConfiguration {

	@Bean
	public GitService gitService() {
		var directoryUtils = new DirectoryUtil();
		return new GitService(directoryUtils);
	}

	@Bean
	public static VelocityEngine velocityEngine(TrustBrokerProperties trustBrokerProperties) {
		return OpenSamlUtil.createVelocityEngine(trustBrokerProperties.getVelocityTemplatePath());
	}

	@Bean
	public static Clock clock() {
		return Clock.systemUTC();
	}

	@Bean
	public static ArtifactCacheService artifactCacheService(ArtifactCacheRepository repository,
			TrustBrokerProperties trustBrokerProperties, Clock clock, MetricsService metricsService) {
		var artifactResolution = trustBrokerProperties.getSaml().getArtifactResolution();
		var lifetime = Duration.ofSeconds(artifactResolution.getArtifactLifetimeSecs());
		var cleanupInterval = Duration.ofSeconds(artifactResolution.getArtifactReapIntervalSecs());
		var storageService = Boolean.TRUE.equals(artifactResolution.getPersistentCache()) ?
				Optional.<StorageService>of(new ArtifactStorageService(repository, clock, cleanupInterval, metricsService)) :
				Optional.<StorageService>empty();
		return new ArtifactCacheService(storageService, lifetime, cleanupInterval);
	}

	// For spring-boot 2.6.0 and later:
	// https://docs.spring.io/spring-boot/docs/2.6.0/reference/html//web.html#web.servlet.embedded-container.customizing.samesite
	// otherwise
	// SameSite Strict does not work as we have top level navigations from the RP for the AuthnRequest
	// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cookie-same-site-00.
	// Lax should be the default, but e.g. Chrome allows POST requests on top of Lax by default, it does not work either
	// None works, which is most permissive (implies secure!), but may be better than relying on browser defaults
	// Discussion on SameSite defaults: https://groups.google.com/a/chromium.org/g/blink-dev/c/AknSSyQTGYs/m/YKBxPCScCwAJ
	// As None is our default, but it can only be combined with the secure flag, we need to disable it for development using http.
	@Bean
	public TomcatContextCustomizer tomcatContextCustomizer(TrustBrokerProperties trustBrokerProperties) {
		// internal setup of traceId (we switch from own UUID to LB inject HEX32 id that will display on the new error screen)
		var traceIdHeader = trustBrokerProperties.getTraceIdHeader();
		if (!TraceSupport.getHttpTraceIdHeaderName().equals(traceIdHeader)) {
			log.info("Switching perimeter traceId from {} to {}", TraceSupport.getHttpTraceIdHeaderName(), traceIdHeader);
			TraceSupport.setHttpTraceIdHeaderName(traceIdHeader);
		}

		// tomcat setup, also see WebUtil.createCookie on other cookie settings applied
		return context -> {
			var cookieProcessor = new TrustbrokerCookieProcessor(trustBrokerProperties);
			context.setCookieProcessor(cookieProcessor);
		};
	}

	// used for asynchronous config refreshes, the threads can be removed later
	@Bean
	public ExecutorService executorService() {
		return Executors.newCachedThreadPool();
	}
}
