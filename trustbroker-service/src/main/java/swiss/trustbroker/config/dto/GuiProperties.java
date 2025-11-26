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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * GUI related configurations.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GuiProperties {

	/**
	 * Resource path where images used in the ClaimsProviderDefinitions are stored.
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.ClaimsProviderMappings
	 * @see swiss.trustbroker.federation.xmlconfig.ClaimsProviderDefinitions
	 */
	private String images;

	/**
	 * Resource path where UI language support files in JSON format are stored.
	 */
	private String translations;

	/**
	 * Resource path where theme assets are stored.
	 */
	private String themeAssets;

	/**
	 * Default language for the UI.
	 */
	private String defaultLanguage;

	/**
	 * Buttons enabled for the theme.
	 */
	@Builder.Default
	private List<GuiButtons> buttons = new ArrayList<>();

	/**
	 * Feature enabled for the theme.
	 */
	@Builder.Default
	private List<GuiFeatures> features = new ArrayList<>();

	/**
	 * Banners.
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private List<Banner> banners = new ArrayList<>();

	/**
	 * Limit the number of banners shown on HRD.
	 * <br/>
	 * For usability reasons, the area consumed by banners should be limited, so the number should be very small.
	 *
	 * @since 1.9.0
	 * @see Banner#getOrder()
	 */
	private Integer maxBanners;

	/**
	 * Attributes for the cookie that stores the user's theme (if there is a theme selector).
	 */
	@Builder.Default
	private CookieProperties themeCookie = new CookieProperties();

	/**
	 * Attributes for the cookie that stores the user's selected language.
	 */
	@Builder.Default
	private CookieProperties languageCookie = new CookieProperties();

	/**
	 * XTB can (via a plugin) support announcements to communicate with the federating user.
	 * These cookie preferences are used to customize it's client side behavior.
	 */
	@Builder.Default
	private CookieProperties announcementCookie = new CookieProperties();

	/**
	 * Browser caching max-age in days for resources that have resource version in the path (a hash or version number).
	 * <br/>
	 * These resources can be cached for a long period as any change will result in a new resource version.
	 *
	 * @since 1.10.0
	 */
	private int versionedResourceMaxAgeDay;

	/**
	 * Paths of resources that have resource version in the path (a hash or version number).
	 *
	 * @since 1.10.0
	 */
	private String[] versionedResourcePaths; // array as it is used as varargs

	/**
	 * Browser caching max-age in seconds for resources that have are tagged with an ETAG (a hash or version number).
	 * <br/>
	 * These resources can be cached for some time after which the ETAG has to be checked.
	 *
	 * @since 1.10.0
	 */
	private int taggedResourceMaxAgeSec;

	/**
	 * @param name
	 * @return Banner with name if defined.
	 */
	public Optional<Banner> getBanner(String name) {
		if (name == null) {
			return Optional.empty();
		}
		return banners.stream()
				.filter(banner -> Objects.equals(banner.getName(), name))
				.findFirst();
	}

	/**
	 * @return all global banners
	 */
	public List<Banner> getGlobalBanners() {
		return banners.stream()
				.filter(Banner::isGlobal)
				.toList();
	}

	/**
	 * @return true if the feature is enabled.
	 */
	@SuppressWarnings("java:S2250") // small List of enum values, linear search is no issue
	public boolean hasFeature(GuiFeatures feature) {
		return features.contains(feature);
	}

}
