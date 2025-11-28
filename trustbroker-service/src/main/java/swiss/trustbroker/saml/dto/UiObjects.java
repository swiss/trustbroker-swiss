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
import java.util.ArrayList;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * UI Objects for HRD: Tiles and banners.
 *
 * @since 1.9.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UiObjects implements Serializable {

	/**
	 * Tiles for CPs.
	 */
	@Builder.Default
	private List<UiObject> tiles = new ArrayList<>();

	/**
	 * Banners.
	 */
	@Builder.Default
	private List<UiBanner> banners = new ArrayList<>();

	/**
	 * Add CP tile.
	 */
	public void addTile(UiObject tile) {
		if (tile == null) {
			return;
		}
		tiles.add(tile);
	}

	/**
	 * Add banner if not yet present.
	 */
	@SuppressWarnings("java:S2250") // list of banners must be very small for UX reasons - using contains is no issue
	public void addBanner(UiBanner banner) {
		if (banner == null) {
			return;
		}
		if (!banners.contains(banner)) {
			banners.add(banner);
		}
	}
}
