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

package swiss.trustbroker.federation.xmlconfig;

/**
 * Modes for SAML Artifact Binding.
 */
public enum ArtifactBindingMode {
	/**
	 * Peer does not support Artifact Binding (inbound or outbound).
	 * Default for outbound.
	 */
	NOT_SUPPORTED,
	/**
	 * 	Outbound: If inbound from RP used Artifact Binding it is also used for the request to CP and/or for the response to RP.
	 * 	Inbound: Artifact Binding allowed, but not required. Default for inbound.
	 * 	Note that for inbound you also need to configure the ProtocolEndpoints for Artifact Binding for the RP/CP,
	 * 	but the default ArtifactBindingMode will then work. For outbound the peer needs to know the metadata or artifact
	 * 	resolution endpoint of XTB.
 	 */
	SUPPORTED,
	/**
	 * Outbound: Always use Artifact Binding towards peer.
	 * Inbound: Require peer to use Artifact Binding.
	 */
	REQUIRED
}
