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

package swiss.trustbroker.config.dto;

/**
 * Mode for Tomcat session.
 */
public enum TomcatSessionMode {
	/**
	 * Single pod or sticky routing, tomcat session reaper collects inactive sessions too.
	 */
	IN_MEMORY,

	/**
	 * Expensive to load session from DB for every getSession call.
	 */
	IN_DB,

	/**
	 * IN_MEMORY with IN_DB backing on failover.
	 */
	MIXED
}
