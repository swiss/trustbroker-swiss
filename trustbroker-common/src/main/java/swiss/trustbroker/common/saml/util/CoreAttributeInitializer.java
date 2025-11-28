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
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.sessioncache.service.AttributeInitializer;

/**
 * This AttributeInitializer runs first, so it will take precedence in case of conflicts.
 */
@Service
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class CoreAttributeInitializer implements AttributeInitializer {

	@Override
	public void init() {
		log.info("Adding core attributes to AttributeRegistry");
		for (var value : CoreAttributeName.values()) {
			AttributeRegistry.putAttributeName(value);
		}
	}

	@Override
	public boolean validate() {
		boolean ok = true;
		for (var value : CoreAttributeName.values()) {
			var registered = AttributeRegistry.forName(value.getName());
			if (registered != value) {
				log.error("CoreAttributeName.{} must be registered by its name - found={}", value.getName(), registered);
				ok = false;
			}
			// validate lazy initialization of namespaceUri
			if (value.getNamespaceUri() == null) {
				log.error("CoreAttributeName.{} namespaceUri must be configured!", value.getName());
				ok = false;
			}
			else {
				registered = AttributeRegistry.forName(value.getNamespaceUri());
				if (registered != value) {
					log.error("CoreAttributeName.{} must be registered by its namespaceUri - found={}", value.getName(),
							registered);
					ok = false;
				}
			}
		}
		return ok;
	}

}
