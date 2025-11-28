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

package swiss.trustbroker.common.setup.config;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.common.exception.TechnicalException;

@Slf4j
public class CustomProxySelector extends ProxySelector {

	@Override
	public List<Proxy> select(URI uri) {
		var sshProxyHost = BootstrapProperties.getSshProxyHost();
		var sshProxyPort = BootstrapProperties.getSshProxyPort();
		try {
			int port = Integer.parseInt(sshProxyPort);
			var sockAddress = new InetSocketAddress(sshProxyHost, port);
			var socksProxy = new Proxy(Proxy.Type.SOCKS, sockAddress);
			log.info("Using outbound proxy with type={} host={} port={}", Proxy.Type.SOCKS, sshProxyHost, sshProxyPort);
			return List.of(socksProxy);
		}
		catch (Exception e) {
			throw new TechnicalException(String.format(
					"Invalid ssh.proxy settings host=%s port=%s: %s",
					sshProxyHost, sshProxyPort, e.getMessage()), e);
		}
	}

	@Override
	public void connectFailed(URI uri, SocketAddress socketAddress, IOException ioException) {
		if (uri == null || socketAddress == null || ioException == null) {
			throw new TechnicalException(String.format("Unexpected null argument(s) uri=%s socketAddress=%s ioException=%s",
					uri, socketAddress, ioException != null ? ioException.getMessage() : null));
		}
	}

}
