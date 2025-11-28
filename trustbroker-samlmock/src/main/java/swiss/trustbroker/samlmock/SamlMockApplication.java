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

package swiss.trustbroker.samlmock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import swiss.trustbroker.common.server.ApplicationMain;

@SpringBootApplication(exclude = {
		DataSourceAutoConfiguration.class, // samlmock inherits the service dependencies but does not use the JPA sub-system,
		SecurityAutoConfiguration.class,
		ManagementWebSecurityAutoConfiguration.class
})
public class SamlMockApplication {

	public static void main(String[] args) {
		ApplicationMain.runBootstrap();
		SpringApplication.run(SamlMockApplication.class, args);
	}

}
