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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import lombok.extern.slf4j.Slf4j;
import org.eclipse.jgit.api.TransportConfigCallback;
import org.eclipse.jgit.transport.HttpTransport;
import org.eclipse.jgit.transport.Transport;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import swiss.trustbroker.common.exception.TechnicalException;

@Slf4j
public class HttpTransportConfig implements TransportConfigCallback {

	private final String accessToken;

	public HttpTransportConfig(String accessToken) {
		var tokenCache = new File(accessToken);
		if (tokenCache.exists()) {
			try {
				this.accessToken = Files.readString(tokenCache.toPath()).strip();
				log.info("Accessing git with access token from {}={}",
						BootstrapProperties.GIT_REPO_TOKEN, tokenCache.getAbsolutePath());
			}
			catch (IOException e) {
				throw new TechnicalException(String.format("Cannot read git token from %s=%s",
						BootstrapProperties.GIT_REPO_TOKEN, tokenCache.getAbsolutePath()), e);
			}
		}
		else if (accessToken.isEmpty() || tokenCache.getPath().startsWith("/")) {
			log.warn("Accessing git anonymously as {}={} does not exist",
					BootstrapProperties.GIT_REPO_TOKEN, accessToken);
			this.accessToken = null;
		}
		else {
			log.info("Accessing git with access token from environment {}={} (length)",
					BootstrapProperties.GIT_REPO_TOKEN, accessToken.length());
			this.accessToken = accessToken;
		}
	}

	@Override
	public void configure(Transport transport) {
		if (transport instanceof HttpTransport httpTransport && accessToken != null) {
			var provider = new UsernamePasswordCredentialsProvider("git", accessToken);
			httpTransport.setCredentialsProvider(provider);
			// proxy settings from java via https.proxyHost/Port or socksProxyHost/Port out of the box
		}
	}

}
