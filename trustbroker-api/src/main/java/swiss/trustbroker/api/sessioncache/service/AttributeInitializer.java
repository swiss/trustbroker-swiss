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

package swiss.trustbroker.api.sessioncache.service;

/**
 * Interface used for configuring custom sets of attributes in the
 * <code>swiss.trustbroker.common.saml.util.AttributeRegistry</code>
 * <br/>
 * Initializers other than trustbroker-service defining an <code>@Order</code> must use positive numbers.
 *
 * @see org.springframework.core.annotation.Order
 */
public interface AttributeInitializer {

	/**
	 * Register values via <code>AttributeRegistry.putAttributeName</code>
	 */
	void init();

	/**
	 * Called at the end of the AttributeRegistry initialization, verify all values are properly configured.
	 *
	 * @return false in case of incomplete configurations. Issues must be logged.
	 */
	boolean validate();

}
