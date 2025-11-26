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

import java.io.Serializable;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Specifies optional banner displayed on top of the screen.
 *
 * @since 1.9.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Banner implements Serializable {

	/**
	 * Name of the banner used for referencing resources (texts, css class).
	 */
	private String name;

	/**
	 * Banner is globally enabled, regardless tiles on the screen.
	 */
	private Boolean global;

	/**
	 * Banner display order for global banners or if no order is defined for the CP.
	 * <br/>
	 * Influences which banners are shown if their number is limited.
	 */
	private Integer order;

	/**
	 * Display banner paragraphs collapsed on a small screen.
	 * <br/>
	 * Default: true, disable if all information is required on small screens as well.
	 *
	 * @since v1.10.0
	 * Previously named collapseParagraphsOnSmallScreen with default false.
	 */
	@Builder.Default
	private Boolean collapseParagraphs = Boolean.TRUE;

	/**
	 * Optional main image.
	 */
	private String mainImage;

	/**
	 * Optional list of secondary images.
	 */
	private List<String> secondaryImages;

	public boolean collapseParagraphs() {
		return Boolean.TRUE.equals(collapseParagraphs);
	}

	public boolean isGlobal() { return Boolean.TRUE.equals(global); }
}
