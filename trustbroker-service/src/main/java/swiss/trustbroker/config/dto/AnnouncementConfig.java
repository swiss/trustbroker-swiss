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

import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Announcement configuration.
 * <br>
 * Potentially breaking changes:
 * <ul>
 *     <li>With 1.10.0 value of attributes changed to Object to allow nested structures.</li>
 * </ul>
 *
 * @see swiss.trustbroker.api.announcements.service.AnnouncementService
 * @see swiss.trustbroker.federation.xmlconfig.AnnouncementRpConfig
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnnouncementConfig {

	/**
	 * Disable the service to discard all announcements.
	 */
	private boolean enabled;

	/**
	 * Schedule for fetching current announcements. Cron expression.
	 */
	private String syncSchedule;

	/**
	 * Path for the local announcements cache.
	 */
	private String cachePath;

	/**
	 * REST endpoint to retrieve current announcements from.
	 */
	private String serviceUrl;

	/**
	 *  After this many minutes of connection loss discard the messages from the cache.
	 * <br/>
	 * Default: 15
	 */
	@Builder.Default
	private int lifeTimeMin = 15;

	/**
	 * TLS truststore used to establish HTTPS connection.
	 */
	private String truststorePath;

	/**
	 * Password for the truststore.
	 * <br/>
	 * Always specify <pre>$PKI_PASSPHRASE</pre> for passwords as a place-holder for the key decryption passphrase to be passed to the running
	 * XTB process.
	 */
	private String truststorePassword;

	/**
	 * A list of application names:
	 * <ul>
	 *     <li>Global announcements are shown to all users on every federated login</li>
	 *     <li>CP related announcements as well, but they can also lead to disabling the HRD tile when the CP 'application' is
	 *     marked as unavailable.</li>
	 * </ul>
	 */
	private List<String> applicationNames;

	/**
	 * App specific queries enabled.
	 */
	private boolean enableAppSpecificQuery;

	/**
	 * Custom attributes that might be needed by the implementation.
 	 */
	private Map<String, Object> attributes;

}
