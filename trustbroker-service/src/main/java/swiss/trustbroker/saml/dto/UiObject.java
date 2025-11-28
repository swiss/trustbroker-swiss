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

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UiObject implements Serializable {

	/**
	 * id uniquely identifies a tile.
	 */
	private String urn;

	/**
	 * disabled signals to the frontend to inactivate the tile.
	 */
	private UiDisableReason disabled;

	/**
	 * order allows to compose multiple tiles in a flexible manner.
	 */
	private Integer order;

	/**
	 * name is displayed on the tile given it's not used as a key into the translation service or overridden by tileTitle.
	 */
	private String name;

	/**
	 * Title for the CP tile and help item.
	 * <br/>
	 * The fallback order (if not defined) is: title > name > ID
	 */
	private String title;

	/**
	 * Text displayed in the CP tile.
	 * <br/>
	 * The fallback order (if not defined) is: description > name > ID
	 */
	private String description;

	/**
	 * Image displayed in the HRD large view.
	 */
	private String image;

	/**
	 * A usually two-character code identifying the CP on small screens.
	 */
	private String shortcut;

	/**
	 * HTML color code identifying the CP on small screens.
	 */
	private String color;

	/**
	 * @return configured order number or a default order at the end of a common CP list (using range [100, 999].
	 */
	@JsonIgnore
	public Integer getOrderWithDefault() {
		return order != null ? order : 999;
	}

}
