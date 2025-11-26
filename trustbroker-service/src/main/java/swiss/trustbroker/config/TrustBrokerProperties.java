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

import java.util.Collections;
import java.util.List;
import java.util.Map;

import lombok.Data;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Configuration;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.config.RegexNameValue;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.setup.config.BootstrapProperties;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.dto.AccessRequestConfig;
import swiss.trustbroker.config.dto.AnnouncementConfig;
import swiss.trustbroker.config.dto.AttributeConfig;
import swiss.trustbroker.config.dto.AuditConfig;
import swiss.trustbroker.config.dto.ContentSecurityPolicies;
import swiss.trustbroker.config.dto.CorsPolicies;
import swiss.trustbroker.config.dto.FrameOptionsPolicies;
import swiss.trustbroker.config.dto.GuiProperties;
import swiss.trustbroker.config.dto.IdmConfig;
import swiss.trustbroker.config.dto.LdapStoreConfig;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.ProfileSelectionConfig;
import swiss.trustbroker.config.dto.QualityOfAuthenticationConfig;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.config.dto.StateCacheProperties;
import swiss.trustbroker.config.dto.Support;
import swiss.trustbroker.config.dto.WsTrustConfig;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;

/**
 * The root of the XTB configuration.
 * <br/>
 * It provides global defaults, some of which can be overridden in the XML configurations.
 */
@Configuration
@ConfigurationProperties(prefix = "trustbroker.config")
@RefreshScope
@Data
public class TrustBrokerProperties {

	/**
	 * Issuer ID used for all SAML2 messages XTB produces.
	 * <br/>
	 * (The perimeterUrl can be used as issuer ID.)
	 */
	private String issuer;

	/**
	 * Perimeter URL that is used to access XTB.
	 */
	private String perimeterUrl;

	/**
	 * Unused / empty for normal setup.
	 * <br/>
	 * In development Angular frontend is used via proxy on <a href="http://localhost:4200">http://localhost:4200</a>
	 */
	private String frontendBaseUrl = "";

	/**
	 * Base path of the keystores configured in the XML configurations.
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.Certificates
	 */
	private String keystoreBasePath;

	/**
	 * GUI related configuration.
	 */
	private GuiProperties gui = new GuiProperties();

	/**
	 * Relative path of the ClaimsProviderDefinitions configuration.
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.ClaimsProviderDefinitions
	 */
	private String claimsDefinitionMapping;

	/**
	 * Relative path of the SetupRP file.
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.RelyingParty
	 */
	private String relyingPartySetup;

	/**
	 * Relative path of the SetupCP file.
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.ClaimsParty
	 */
	private String claimsProviderSetup;

	/**
	 * Relative path of the SsoGroupSetup file
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.SsoGroupSetup
	 */
	private String ssoGroupSetup;

	/**
	 * Relative path of the Groovy scripts.
	 * <br/>
	 * Potentially breaking changes:
	 * <ul>
	 *     <li>With 1.7.0 the last part was extracted into <code>globalScriptPath</code>.</li>
	 * </ul>
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.Script
	 */
	private String scriptPath;

	/**
	 * Relative path to <code>scriptPath</code> of the global Groovy scripts.
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.Script
	 * @since 1.7.0
	 */
	private String globalScriptPath;

	/**
	 * Relative path to <code>definition</code> of the global profiles.
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.RelyingParty#getBase()
	 * @since 1.7.0
	 */
	private String globalProfilesPath;

	/**
	 * Default signer.
	 */
	private KeystoreProperties signer;

	/**
	 * Signer used during rollover.
	 */
	private KeystoreProperties rolloverSigner;

	/**
	 * Configuration for optional IDM integration.
	 */
	private IdmConfig idm = new IdmConfig();

	/**
	 * Configuration for optional LDAP integration.
	 */
	private LdapStoreConfig ldap = new LdapStoreConfig();

	/**
	 * Configuration for attributes
	 */
	private AttributeConfig attributes = new AttributeConfig();

	/**
	 * Secret for administrative APIs.
	 * <br/>
	 * E.g. the one to trigger immediate config reload.
	 */
	private String adminSecret;

	/**
	 * SSH key path. Set during bootstrap, not via application.yml.
	 */
	private String sshConfigKeyPath;

	/**
	 * Git repo. Set during bootstrap, not via application.yml.
	 */
	private String remoteRepoUri;

	/**
	 * Configuration branch. Set during bootstrap, not via application.yml.
	 */
	private String configBranch;

	/**
	 * Configuration path. Set during bootstrap, not via application.yml.
	 */
	private String configurationPath;

	/**
	 * WS-Trust protocol configuration.
	 */
	private WsTrustConfig wstrust = new WsTrustConfig();

	/**
	 * SAML protocol configuration.
	 */
	private SamlProperties saml;

	/**
	 * OIDC protocol configuration.
	 */
	private OidcProperties oidc;

	/**
	 * Security check configuration.
	 */
	private SecurityChecks security = new SecurityChecks();

	/**
	 * HTTP CORS configuration.
	 */
	private CorsPolicies cors = new CorsPolicies();

	/**
	 * HTTP CSP configuration.
	 */
	private ContentSecurityPolicies csp = new ContentSecurityPolicies();

	/**
	 * HTTP Frame Options configuration.
	 */
	private FrameOptionsPolicies frameOptions = new FrameOptionsPolicies();

	/**
	 * Run session and auth cache in DB
	 * <br/>
	 * Default: true
	 */
	private boolean serverMultiProcessed = true;

	/**
	 * Development feature flag to simulate multi-pod behavior with a single service.
	 * <br/>
	 * Default: false
	 */
	private boolean serverSingleUser = false;

	/**
	 * Support features.
	 * <br/>
	 * Default: null, disabled
	 *
	 * @since 1.7.0
	 */
	private Support support;

	/**
	 * Audit configuration.
	 *
	 * @since 1.8.0
	 */
	private AuditConfig audit = new AuditConfig();

	/**
	 * Default should be secure, disable in DEV only if needed for picky user-agents.
	 * <br/>
	 * Default: true
	 */
	private boolean secureBrowserHeaders = true;

	/**
	 * Use session cookie for SSO, should always be true.
	 * <br/>
	 * Default: true
	 */
	private boolean useSessionCookieForSso = true;

	/**
	 * Global default cookie sameSite flag.
	 * <br/>
	 * Default: None
	 */
	private String cookieSameSite = WebUtil.COOKIE_SAME_SITE_NONE;

	/**
	 * HTTP header that supplies a request trace ID.
	 */
	private String traceIdHeader;

	/**
	 * Session lifetime for non-SSO login exchanges. State used to correlate pending AuthnRequest with Response received from
	 * CP after a user has logged in there. A too short value leads to aborted logins when users continue
	 * their login on the CP after a longer delay.
	 */
	private int sessionLifetimeSec;

	/**
	 * Session lifetime during which SSO is possible on XTB.
	 */
	private int ssoSessionLifetimeSec;

	/**
	 * Global minimum for QoA level for SSO.
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.SecurityPolicies
	 */
	private int ssoMinQoaLevel;

	/**
	 * Stop waiting for SLO notifications after that and submit LogoutResponse.
	 * <br/>
	 * Default: 2000
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.SloResponse
	 */
	private int sloNotificationTimoutMillis = 2000;

	/**
	 * Minimum wait in case of fire-and-forget SLO notifications
	 * <br/>
	 * Default: 200
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.SloResponse
	 */
	private int sloNotificationMinWaitMillis = 200;

	/**
	 * Global default for SAML logout responses. Relative path or known absolute URL (e.g. to confirmation page).
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.SloResponse
	 */
	private String sloDefaultSamlDestinationPath;

	/**
	 * Global default for OIDC logout responses. Relative path or known absolute URL (e.g. to confirmation page).
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.SloResponse
	 */
	private String sloDefaultOidcDestinationPath;

	/**
	 * SSO session ID policy.
	 *
	 * @see swiss.trustbroker.config.dto.SsoSessionIdPolicy
	 */
	private String ssoSessionIdPolicy;

	/**
	 * Prefix for PEP (Policy Enforcement Point) issuer matching.
	 */
	private String sloPepIssuerIdPrefix;

	/**
	 * Parts of issuer ID ignored when determining Single Logout (SLO).
	 * These are common parts of RP aliases.
	 *
	 * @see ClaimsProvider
	 */
	private String[] sloIssuerIdDropPatterns;

	/**
	 * SAML responder error handling enabled.
	 * <br/>
	 * Default: false
	 */
	private boolean handleResponderErrors;

	/**
	 * User request switch to Enterprise IDP feature flag. If enabled XTB will redirect the user to the intranet IDP when
	 * requested.
	 * <br/>
	 * Default: false
	 *
	 * @deprecated XTB does not support CP/IDP switching based on CP error responses anymore with v1.10.
	 */
	@Deprecated(since = "1.9.0")
	private boolean handleEnterpriseSwitch;

	/**
	 * Intranet IDP ID that can be used for CP filtering in HRD.
	 *
	 * @deprecated Replaced by the 'first' marker on the network, e.g. INTRANET-first.
	 */
	@Deprecated(since = "1.9.0")
	private String enterpriseIdpId;

	/**
	 * Broker IDP ID that can be used for CP filtering in HRD.
	 *
	 * @see swiss.trustbroker.api.homerealmdiscovery.service.HrdService
	 * @deprecated Replaced by the 'first' marker on the network, e.g. INTERNET-first.
	 */
	@Deprecated(since = "1.9.0")
	private String brokerIdpId;

	/**
	 * Public IDP ID that can be used for CP filtering in HRD.
	 *
	 * @deprecated Replaced by the 'first' marker on the network, e.g. INTERNET-first.
	 */
	@Deprecated(since = "1.9.0")
	private String publicIdpId;

	/**
	 * Mobile IDP ID that is used for CP filtering in HRD when XTB is accessed via configured IP addresses
	 * (mobileGatewayIpRegex).
	 * Special case: A single IDP that can be identified by its IP address and then automatically dispatched to the that CP.
	 */
	private String mobileIdpId;

	/**
	 * HTTP GET query parameter (or POST parameter) that can be sent to request selection of an IDP instead of showing the HRD
	 * screen.
	 * <br/>
	 * See <code>ClaimsProvider</code> for the fields matched against this parameter.
	 *
	 * @see ClaimsProvider#getHrdHintAlias()
	 * @since 1.10.0
	 */
	private String hrdHintParameter;

	/**
	 * HTTP header / cookie name to allow a testing framework to pass a CP to be selected in HRD.
	 * <br/>
	 * For normal applications, setting HTTP headers or cookies is usually not convenient (see <code>hrdHintParameter</code>).
	 * <br/>
	 * See <code>ClaimsProvider</code> for the fields matched against this parameter.
	 * <br/>
	 * Note: This is ignored if the request is not from INTRANET (see <code>hrdHintTestAllowedFromInternet</code>).
	 * If set, it also suppresses the AccessRequest.
	 *
	 * @see ClaimsProvider#getHrdHintAlias()
	 * @since 1.10.0
	 */
	private String hrdHintTestParameter;

	/**
	 * Allow hrdHintTestParameter without a network header or from INTERNET.
	 * <br/>
	 * Note: In case you use AccessRequest, only enable this if AccessRequest may be skipped without security impact.
	 * <br/>
	 * Default: false
	 *
	 * @since 1.10.0
	 */
	private Boolean hrdHintTestAllowedFromInternet = Boolean.FALSE;

	/**
	 * Autologin cookie that can be used for CP filtering in HRD.
	 */
	private String publicAutoLoginCookie;

	/**
	 * Network configuration.
	 */
	private NetworkConfig network;

	/**
	 * Configuration for DB state cache.
	 */
	private StateCacheProperties stateCache = new StateCacheProperties();

	/**
	 * XTB version information for the GUI
	 */
	private String versionInfo;

	/**
	 * Comma-separated list of supported TLS versions.
	 */
	private String supportedTlsVersions;

	/**
	 * Development feature:
	 * Set this to <pre>../trustbroker-service/src/main/resources</pre>
	 * for faster template development - templates will be loaded from the file system on each access
	 */
	private String velocityTemplatePath;

	/**
	 * Announcement configuration.
	 */
	private AnnouncementConfig announcements = new AnnouncementConfig();

	/**
	 * QoA configuration.
	 */
	private QualityOfAuthenticationConfig qoa = new QualityOfAuthenticationConfig();

	/**
	 * Profile selection configuration.
	 */
	private ProfileSelectionConfig profileSelection = new ProfileSelectionConfig();

	/**
	 * Access request configuration.
	 */
	private AccessRequestConfig accessRequest = new AccessRequestConfig();

	/**
	 * Skinny SAML messages reducing the size of the messages (large SAML messages on picky perimeters might block).
	 * <br/>
	 * Default: a,no-type
	 */
	private String skinnyAssertionNamespaces = OpenSamlUtil.SKINNY_ALL;

	/**
	 * Legacy clients that get the skinny HRD screen (monitor, testing).
	 */
	private List<RegexNameValue> skinnyHrdTriggers;

	/**
	 * HTTP markers identifying monitoring clients that cannot deal with new features.
	 */
	private List<RegexNameValue> monitoringHints;

	//  As bootstrap works without spring, we need to handle a few boostrap parameters via ENV and/or system properties.
	public void setGitParamsFromEnv() {
		setSshConfigKeyPath(BootstrapProperties.getGitSshKeyPath());
		setConfigurationPath(BootstrapProperties.getGitConfigCache());
		setConfigBranch(BootstrapProperties.getGitConfigBranch());
		setRemoteRepoUri(BootstrapProperties.getGitRepoUrl());
	}

	public int getSessionLifetimeSec(boolean ssoEnabled) {
		return ssoEnabled ? ssoSessionLifetimeSec : sessionLifetimeSec;
	}

	public boolean isPepIssuerMatchingEnabled(String id) {
		return StringUtils.isNotEmpty(this.getSloPepIssuerIdPrefix()) &&
				ArrayUtils.isNotEmpty(this.getSloIssuerIdDropPatterns()) &&
				id.startsWith(this.getSloPepIssuerIdPrefix());
	}

	public String getSamlConsumerUrl() {
		return saml != null ? saml.getConsumerUrl() : null;
	}

	public Map<String, Integer> getQoaMap() {
		if (this.qoa == null || this.qoa.getMapping() == null) {
			return Collections.emptyMap();
		}
		return this.qoa.getMapping();
	}

}
