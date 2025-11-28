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

package swiss.trustbroker.saml.dto;

import java.io.Serializable;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Banner for HRD.
 *
 * @see swiss.trustbroker.config.dto.Banner
 *
 * @since 1.9.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UiBanner implements Serializable {

	/**
	 * Name of the banner referencing configuration.
	 */
	private String name;

	/**
	 * Main image of banner.
	 */
	private String mainImage;

	/**
	 * Secondary images of banner.
	 */
	private List<String> secondaryImages;

	/**
	 * True if paragraphs of banner are shown collapsed on a small screen.
	 */
	private boolean collapseParagraphs;

	/**
	 * Order of the banner.
	 */
	private Integer order;
}
