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

package swiss.trustbroker.oidcmock;

import java.util.Map;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Custom configuration of custom clientClaims
 */
@Configuration
@ConfigurationProperties(prefix = "oidcmock")
@Data
public class OidcMockProperties {

	private boolean encryptIdToken = false;

	private boolean signEncIdToken = true;

	private String encryptionAlgorithm = JWEAlgorithm.RSA_OAEP_256.getName();

	private String encryptionMethod = EncryptionMethod.A256GCM.getName();

	private Map<String, Map<String, String>> clients;
}
