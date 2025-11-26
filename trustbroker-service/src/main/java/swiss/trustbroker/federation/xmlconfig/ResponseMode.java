/*
 * Copyright (C) 2024 trustbroker.swiss team BIT
 *
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY,
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package swiss.trustbroker.federation.xmlconfig;

import jakarta.xml.bind.annotation.XmlEnumValue;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * OIDC response modes.
 * <br/>
 * Note: Currently, only <code>query</code> and <code>form_post</code> responses from an OIDC CP are supported.
 *
 * @since 1.10.0
 */
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
@SuppressWarnings("java:S125")
public enum ResponseMode {

	@XmlEnumValue("query")
	QUERY("query"),

	@XmlEnumValue("form_post")
	FORM_POST("form_post");

	/* Values not yet supported given for reference, but commented out to ensure the generated xsd does not include them:

	@XmlEnumValue("fragment")
	FRAGMENT("fragment"),

	@XmlEnumValue("query.jwt")
	QUERY_JWT("query.jwt"),

	@XmlEnumValue("fragment.jwt")
	FRAGMENT_JWT("fragment.jwt"),

	@XmlEnumValue("form_post.jwt")
	FORM_POST_JWT("form_post.jwt"),

	@XmlEnumValue("jwt")
	JWT("jwt");

	*/

	private final String name;

}
