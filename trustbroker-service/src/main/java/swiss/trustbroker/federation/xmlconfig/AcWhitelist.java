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

package swiss.trustbroker.federation.xmlconfig;

import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.BiPredicate;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.common.util.WebUtil;

/**
 * Whitelist of Assertion consumer service URLs / OIDC redirect URLs.
 */
@XmlRootElement(name = "ACWhitelist")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@Slf4j
public class AcWhitelist implements Serializable {

	/**
	 * Use the first entry as default if the RP does not send an ACS URL.
	 * <br/>
	 * So far only supported for SAML.
	 * <br/>
	 * Default: false
	 *
	 * @since 1.11.0
	 */
	@XmlAttribute(name = "useDefault")
	@Builder.Default
	private Boolean useDefault = false;

	/**
	 * List of allowed URLs.
	 */
	@XmlElement(name = "ACUrl")
	private List<String> acUrls;

	@XmlTransient
	private List<URI> acNetUrls;

	@XmlTransient
	private List<String> redirectUrls;

	@XmlTransient
	private List<String> origins;

	/**
	 * Allowed frame ancestors for iframes.
	 * <br/>
	 * Overrides origins derived from ACUrl if set (even if configured as an empty list).
	 *
	 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors">CSP frame-ancestors</a>
 	 */
	@XmlElement(name = "FrameAncestor")
	private List<String> frameAncestors;

	public AcWhitelist() {
		this(null, null, null, null, null, null);
	}

	public AcWhitelist(List<String> acUrls) {
		this(null, acUrls, null, null, null, null);
	}

	public AcWhitelist(Boolean useDefault, List<String> acUrls, List<URI> acNetUrls, List<String> redirectUrls,
			List<String> origins,
			List<String> frameAncestors) {
		this.useDefault = useDefault;
		this.acNetUrls = acNetUrls;
		this.origins = origins;
		this.redirectUrls = redirectUrls;
		setAcUrls(acUrls);
		this.frameAncestors = frameAncestors;
	}

	public void setAcUrls(List<String> acUrls) {
		this.acUrls = acUrls == null ? new ArrayList<>() : acUrls;
		calculateDerivedUrls();
	}

	public void calculateDerivedUrls() {
		this.acUrls = acUrls == null ? new ArrayList<>() : acUrls;
		this.redirectUrls = new ArrayList<>();
		this.acNetUrls = new ArrayList<>();
		this.origins = new ArrayList<>();
		for (var acUrl : this.acUrls) {
			var url = WebUtil.getValidatedUri(acUrl);
			if (url == null || !url.isAbsolute()) {
				log.info("Ignoring ACUrl={} - it is invalid, relative or a regex", acUrl);
			}
			else {
				this.acNetUrls.add(url);
				var validOrigin = WebUtil.getValidOrigin(url);
				if (validOrigin == null) {
					// happens e.g. with wildcards in domain names
					log.info("Ignoring url={} having scheme='{}' host='{}' authority='{}' (HINT: No regexp on these fields)",
							url, url.getScheme(), url.getHost(), url.getAuthority());
				}
				else {
					this.origins.add(validOrigin);
				}
				if (url.getRawFragment() == null) {
					this.redirectUrls.add(acUrl);
				}
				else {
					log.info("ACUrl={} contains a fragment - not a valid redirect URL", acUrl);
				}
			}
		}
	}

	public List<String> getFrameAncestorsWithFallback() {
		if (frameAncestors != null) {
			return frameAncestors;
		}
		return origins;
	}

	public Optional<String> getDefault() {
		if (!Boolean.TRUE.equals(useDefault) || CollectionUtils.isEmpty(acUrls)) {
			return Optional.empty();
		}
		return Optional.of(acUrls.get(0));
	}

	public Optional<String> findFirst(BiPredicate<String, String> matcher, String checkUrl) {
		if (CollectionUtils.isEmpty(acUrls)) {
			return Optional.empty();
		}
		return acUrls.stream().filter(acUrl -> matcher.test(acUrl, checkUrl)).findFirst();
	}

}
