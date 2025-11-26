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

package swiss.trustbroker.oidc.session;

/**
 * SessionRegistry that used to integrate Spring auth server OIDC session with XTB SSO Session.
 * We moved one level down to the TomcatSessionManager also replicating sessions to other service instances/pods.
 * Not a Component anymore and kept for documentation only.
 */
@SuppressWarnings("java:S2094")
public class SpringSessionRegistry // implements SessionRegistry, ApplicationListener<AbstractSessionEvent>
{
}
