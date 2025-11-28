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

package swiss.trustbroker.common.saml.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.Init;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import swiss.trustbroker.common.exception.TechnicalException;

@Slf4j
public class SamlInitializer {

	private static class SamlSubSystemInitializer {

		private SamlSubSystemInitializer() {}

		static {
			SamlInitializer.reInitSamlSubSystem();
		}

		private static void init() {
			// init triggered static initializer to ensure it runs only once in a thread-safe way
		}
	}


	private SamlInitializer() {
	}

	/**
	 * Initialize XML security and the SAML libraries in the correct order once only.
	 */
	public static void initSamlSubSystem() {
		SamlSubSystemInitializer.init();
	}

	/**
	 * Initialize XML security and the SAML libraries in the correct order even if already done. For special purposes like tests.
	 */
	public static void reInitSamlSubSystem() {
		reInitXmlSecurity();
		reInitOpenSaml();
		validateInitialization();
	}

	/**
	 * Initialize Apache XML security library even if already done. For special purposes like tests.
	 */
	public static void reInitXmlSecurity() {
		// XML security
		System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
		Init.init();
		log.info("Apache XML security initialized on classLoader={}", SamlInitializer.class.getClassLoader());
	}

	/**
	 * Initialize OpenSAML library even if already done. For special purposes like tests.
	 */
	public static void reInitOpenSaml() {
		try {
			// OpenSAML library
			InitializationService.initialize();
			registerCompatibilityWorkarounds();
			log.info("OpenSAML initialized on classLoader={}", SamlInitializer.class.getClassLoader());
		}
		catch (InitializationException ex) {
			throw new TechnicalException(String.format("OpenSAML initialization failed: %s", ex.getMessage()), ex);
		}

		validateInitialization();
	}

	private static void registerCompatibilityWorkarounds() {
		SamlIoUtil.overrideUnmarshaller(CompatEndPointReferenceUnmarshaller.QNAME, new CompatEndPointReferenceUnmarshaller());
		log.info("Compatibility workarounds registered on classLoader={}", SamlInitializer.class.getClassLoader());
	}

	private static void validateInitialization() {
		// Check post conditions (see SAMLFactory)
		if (SecurityConfigurationSupport.getGlobalEncryptionConfiguration() == null) {
			throw new TechnicalException("OpenSAML initialization not successful");
		}
	}

}
