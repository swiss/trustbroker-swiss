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

package swiss.trustbroker;

import java.io.File;
import java.util.Collection;
import java.util.List;

import jakarta.annotation.PostConstruct;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.api.sessioncache.service.AttributeInitializer;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.AttributeRegistry;
import swiss.trustbroker.common.setup.config.BootstrapProperties;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.config.AppConfigService;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderDefinitions;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.homerealmdiscovery.service.WebResourceProvider;
import swiss.trustbroker.homerealmdiscovery.util.ClaimsProviderUtil;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartySetupUtil;
import swiss.trustbroker.oidc.cache.service.OidcMetadataCacheService;
import swiss.trustbroker.script.service.ScriptService;

/**
 * Initialize everything based on the spring container's initialization procedure.
 */
@Component
@Slf4j
@AllArgsConstructor
public class ApplicationInitializer {

	private static final String DIRECTORY_LATEST = GitService.CONFIGURATION_PATH_SUB_DIR_LATEST;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties trustBrokerProperties;

	private final AppConfigService appConfigService;

	private final ScriptService scriptService;

	private final GitService gitService;

	private final List<AttributeInitializer> attributeInitializers;

	private final List<IdmQueryService> idmQueryServices;

	private final GlobalExceptionHandler globalExceptionHandler;

	private final WebResourceProvider resourceProvider;

	private final OidcMetadataCacheService oidcMetadataCacheService;

	@EventListener(ContextRefreshedEvent.class)
	@PostConstruct
	public void onApplicationEvent() {
		try {
			loadConfiguration();
		}
		catch (TechnicalException ex) {
			globalExceptionHandler.logException(ex);
			throw new IllegalStateException("Unable to (re-)configure XTB, fix configuration problem: " + ex.getInternalMessage());
		}
		catch (Exception other) {
			globalExceptionHandler.logException(other);
			throw new IllegalStateException("Unable to (re-)configure XTB, fix configuration problem: " + other);
		}
	}

	public void loadConfiguration() {
		log.info("Propagating bootstrap configuration to spring setup");
		trustBrokerProperties.setGitParamsFromEnv();

		initAttributes();

		var claimsProviderDefinitions = ClaimsProviderUtil.loadClaimsProviderDefinitions(
				trustBrokerProperties.getConfigurationPath() + DIRECTORY_LATEST +
						trustBrokerProperties.getClaimsDefinitionMapping());

		var relyingPartySetup = ClaimsProviderUtil.loadRelyingPartySetup(
				trustBrokerProperties.getConfigurationPath() + DIRECTORY_LATEST +
						trustBrokerProperties.getRelyingPartySetup());

		var claimsProviderSetup = ClaimsProviderUtil.loadClaimsProviderSetup(
				trustBrokerProperties.getConfigurationPath() + DIRECTORY_LATEST +
						trustBrokerProperties.getClaimsProviderSetup());

		var ssoGroupSetup = ClaimsProviderUtil.loadSsoGroups(
				trustBrokerProperties.getConfigurationPath() + DIRECTORY_LATEST +
						trustBrokerProperties.getSsoGroupSetup());

		// post-conditions from loading config
		Assert.notNull(claimsProviderDefinitions,"No ClaimsProviderDefinitions definition found");
		Assert.notNull(relyingPartySetup, "No SetupRP files found");
		Assert.notNull(claimsProviderSetup,"No SetupCP files found");
		Assert.notNull(ssoGroupSetup, "No SSO group setup found");

		// load up-to-date scripts for validation
		scriptService.prepareRefresh();

		// load standard configurations
		loadAllRelyingParties(relyingPartySetup, claimsProviderSetup, claimsProviderDefinitions);

		// PKI setup, note that RP/CP unrelated PKI setup cannot be reloaded dynamically, we need to restart then
		appConfigService.checkAndLoadRelyingPartyCertificates(relyingPartySetup);

		// post-conditions again
		appConfigService.checkClaimAndRpMatch(relyingPartySetup, ssoGroupSetup);

		appConfigService.filterInvalidRelyingParties(relyingPartySetup);
		appConfigService.filterInvalidClaimsParties(claimsProviderSetup);

		// assembly
		relyingPartyDefinitions.setClaimsProviderDefinitions(claimsProviderDefinitions);
		relyingPartyDefinitions.setRelyingPartySetup(relyingPartySetup);
		relyingPartyDefinitions.setClaimsProviderSetup(claimsProviderSetup);
		relyingPartyDefinitions.setSsoGroupSetup(ssoGroupSetup);
		appConfigService.checkAndLoadCpCertificates(claimsProviderSetup);
		appConfigService.validateScripts(claimsProviderSetup);
		relyingPartyDefinitions.loadOidcConfiguration(trustBrokerProperties.getOidc());
		relyingPartyDefinitions.loadAccessRequestConfigurations();

		// OIDC registry populate
		appConfigService.checkAndUpdateOidcRegistry(relyingPartySetup);

		// load scripts, this MUST be last as the refresh will swap the script registry, and we are not transactional here
		scriptService.activateRefresh();
		gitService.refresh();

		resourceProvider.flushCache();

		appConfigService.updateMetrics();

		// OIDC remote calls at the end
		oidcMetadataCacheService.triggerRefreshConfigurations();
	}

	private void initAttributes() {
		// Attributes are not overwritten. The order is
		// - other AttributeName sets
		// - CoreAttributeNames (guaranteed by Ordering of the Services)
		// - config
		for (var initializer : attributeInitializers) {
			initializer.init();
		}
		var attributes = trustBrokerProperties.getAttributes().getDefinitions();
		if (!CollectionUtils.isEmpty(attributes)) {
			log.info("Adding trustroker.config.attributes to AttributeRegistry");
			for (var attribute : attributes) {
				AttributeRegistry.updateAttributeNameFromConfig(attribute);
			}
		}
		var ok = true;
		for (var initializer : attributeInitializers) {
			ok &= initializer.validate();
		}
		if (!ok) {
			throw new TechnicalException("AttributeRegistry not properly configured. "
					+ "HINT: Adapt trustbroker.config.attributes to fix the errors above");
		}
	}

	private void loadAllRelyingParties(RelyingPartySetup relyingPartySetup, ClaimsProviderSetup claimsProviderSetup, ClaimsProviderDefinitions claimsProviderDefinitions) {
		String configurationPath = trustBrokerProperties.getConfigurationPath();
		String newConfigPath = AppConfigService.getConfigCachePath(configurationPath) +
						BootstrapProperties.getSpringProfileActive() + File.separatorChar;
		Collection<RelyingParty> relyingParties = relyingPartySetup.getRelyingParties();
		RelyingPartySetupUtil.loadRelyingParty(
				relyingParties, trustBrokerProperties.getConfigurationPath() +
						GitService.CONFIGURATION_PATH_SUB_DIR_LATEST + RelyingPartySetupUtil.DEFINITION_PATH, newConfigPath,
				trustBrokerProperties, idmQueryServices, scriptService, claimsProviderSetup, claimsProviderDefinitions);
	}
}
