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

import lombok.extern.slf4j.Slf4j;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.URIish;
import org.eclipse.jgit.transport.sshd.KeyPasswordProvider;

@Slf4j
public class SshKeyPasswordProvider implements KeyPasswordProvider {

	public SshKeyPasswordProvider(CredentialsProvider provider) {
		// Bad design, we only try with the single key we support
	}

	@Override
	public char[] getPassphrase(URIish uri, int attempt) throws IOException {
		var passphrase = System.getenv("SSH_KEY_PASS");
		if (passphrase != null) {
			return passphrase.toCharArray();
		}
		throw new IOException(String.format(
				"Seems your sshKey=%s is encrypted and we could not find a passphrase. Please mount an un-encrypted key"
						+ " from a K8S secret or inject a SSH_KEY_PASS to de-crypt it in your DEV process.",
				BootstrapProperties.getGitSshKeyPath()));
	}

	@Override
	public void setAttempts(int maxNumberOfAttempts) {
		// Bad design, we only try once which is the default of getAttempts
	}

	@Override
	public boolean keyLoaded(URIish uri, int attempt, Exception error) {
		return false;
	}

}
