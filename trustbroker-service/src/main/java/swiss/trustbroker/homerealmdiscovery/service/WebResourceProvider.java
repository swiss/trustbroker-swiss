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

package swiss.trustbroker.homerealmdiscovery.service;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.FileServerUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;

/**
 * Caching provider for web resources.
 */
@Service
@AllArgsConstructor
@Slf4j
public class WebResourceProvider {

	static final String CONTENT_TYPE_SVG = "image/svg+xml";

	private record CacheKey(String path, String resource) {}

	private record CacheEntry(FileServerUtil.FileContent content, String etag, Instant cacheTime) {}

	private final TrustBrokerProperties trustBrokerProperties;

	private final Map<CacheKey, CacheEntry> cache = new ConcurrentHashMap<>();

	public void getImageByNameWithMediaType(HttpServletRequest request, HttpServletResponse response, String imageName) {
		var imagePath = trustBrokerProperties.getGui().getImages();
		var key = new CacheKey(imagePath, imageName);
		var entry = getCachedResource(key, CONTENT_TYPE_SVG);
		returnResource(request, response, key, entry);
	}

	public void getThemeAsset(HttpServletRequest request, HttpServletResponse response, String resource) {
		var assetsPath = trustBrokerProperties.getGui().getThemeAssets();
		var key = new CacheKey(assetsPath, resource);
		var entry = getCachedResource(key, null);
		returnResource(request, response, key, entry);
	}

	public void getTranslationForLanguage(HttpServletRequest request, HttpServletResponse response, String language) {
		var translationsPath = trustBrokerProperties.getGui().getTranslations();
		var defaultLanguage = trustBrokerProperties.getGui().getDefaultLanguage();
		var versionInfo = trustBrokerProperties.getVersionInfo();
		var key = new CacheKey(translationsPath, language);
		var entry = getCachedTranslationFile(key, defaultLanguage, versionInfo);
		returnResource(request, response, key, entry);
	}

	private void returnResource(HttpServletRequest request, HttpServletResponse response, CacheKey key, CacheEntry cacheEntry) {
		try {
			// https://datatracker.ietf.org/doc/html/rfc7232#section-4.1
			WebUtil.addCacheHeaders(response, trustBrokerProperties.getGui().getTaggedResourceMaxAgeSec(), cacheEntry.etag(),
					cacheEntry.cacheTime(), Instant.now());
			var ifNoneMatch = request.getHeader(HttpHeaders.IF_NONE_MATCH);
			var ifModifiedSince = request.getHeader(HttpHeaders.IF_MODIFIED_SINCE);
			var cached = WebUtil.isCached(cacheEntry.etag(), ifNoneMatch, cacheEntry.cacheTime(), ifModifiedSince);
			log.debug("Returning {}modified resource={} from path={} etag={} cacheTime={} : ifNoneMatch={} ifModifiedSince={}",
					cached ? "not " : "", key.resource(), key.path(), cacheEntry.etag(), cacheEntry.cacheTime(),
							ifNoneMatch, ifModifiedSince);
			if (cached) {
				// Content-length is optional, but if set would need to be set to the same value as for OK:
				// https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.2
				response.setStatus(HttpStatus.NOT_MODIFIED.value());
			}
			else {
				response.setStatus(HttpStatus.OK.value());
				response.setContentType(cacheEntry.content().contentType());
				response.setContentLength(cacheEntry.content().data().length);
				response.getOutputStream().write(cacheEntry.content().data());
			}
		}
		catch (IOException ex) {
			throw new TechnicalException(
					String.format("Could not output resource=\"%s\" from path=\"%s\" : %s",
							key.resource(), key.path(), ex.getMessage()), ex);
		}
	}

	private CacheEntry getCachedResource(CacheKey key, String contentType) {
		return cache.computeIfAbsent(key, miss -> getFileContent(miss, contentType));
	}

	private CacheEntry getCachedTranslationFile(CacheKey key, String defaultLanguage, String versionInfo) {
		return cache.computeIfAbsent(key, miss -> getTranslationFile(miss, defaultLanguage, versionInfo));
	}

	private static CacheEntry getTranslationFile(CacheKey key, String defaultLanguage, String versionInfo) {
		var content = FileServerUtil.readTranslationFile(key.path(), key.resource(), defaultLanguage, versionInfo);
		return cacheFileContent(key, content);
	}

	private static CacheEntry getFileContent(CacheKey key, String contentType) {
		var content = FileServerUtil.readFileContent(key.path(), key.resource(), contentType);
		return cacheFileContent(key, content);
	}

	private static CacheEntry cacheFileContent(CacheKey key, FileServerUtil.FileContent content) {
		// store with quotes, as the browser also sends the value quoted
		var etag = '"' + Long.toHexString(Arrays.hashCode(content.data())) + '"';
		log.info("Cached resource=\"{}\" from path=\"{}\" etag={} contentType=\"{}\" from file=\"{}\"",
				key.resource(), key.path(), etag, content.contentType(), content.name());
		return new CacheEntry(content, etag, Instant.now());
	}

	public void flushCache() {
		cache.clear();
		log.info("Flushed web resource cache");
	}

	int cacheSize() {
		return cache.size();
	}

}
