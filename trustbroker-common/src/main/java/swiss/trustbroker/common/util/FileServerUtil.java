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

package swiss.trustbroker.common.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.springframework.http.MediaType;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;

@Slf4j
public class FileServerUtil {

	@SuppressWarnings("java:S6218") // not used as collection key, bad equals and hashCode due to array do not matter
	public record FileContent(String name, String contentType, byte[] data) {

	}

	private static final String VERSION_INFO_PLACEHOLDER = "VERSION@STAGE";

	private FileServerUtil() {
	}

	public static FileContent readFileContent(String directoryPath, String filePath, String contentType) {
		var file = getSanitizedFile(directoryPath, filePath, false);
		try {
			contentType = extractContentType(file, contentType);
			var bytes = Files.readAllBytes(file.toPath());
			return new FileContent(file.getPath(), contentType, bytes);
		}
		catch (IOException ex) {
			throw new TechnicalException(String.format("Could not read file=%s denied. Check path=%s with error %s",
					filePath, file.getAbsolutePath(), ex.getMessage()));
		}
	}

	private static String extractContentType(File file, String contentType) throws IOException {
		if (contentType == null) {
			contentType = Files.probeContentType(file.toPath());
			log.debug("Derived contentType={} for file={}", contentType, file.getPath());
		}
		return contentType;
	}

	public static FileContent readTranslationFile(String translationsPath, String language, String defaultLanguage,
			String versionInfo) {
		var translationFile = getTranslationFile(translationsPath, defaultLanguage, language);
		try (var translationStream = new FileInputStream(translationFile)) {
			// apply our own version info from the installation
			var jsonStr = IOUtils.toString(translationStream, Charset.defaultCharset());
			var jsonResult = applyVersionInfo(jsonStr, versionInfo);
			return new FileServerUtil.FileContent(translationFile.getPath(),
					MediaType.APPLICATION_JSON_VALUE,
					jsonResult.getBytes(StandardCharsets.UTF_8));
		}
		catch (IOException ex) {
			throw new TechnicalException(String.format("Could not read translation for language=%s denied. Check path=%s "
					+ "with error %s", language, translationFile.getAbsolutePath(), ex.getMessage()));
		}
	}

	private static File getTranslationFile(String translationsPath, String defaultLanguage, String language) {
		var nameUnsafe = language + ".json";
		var translationFile = getSanitizedFile(translationsPath, nameUnsafe, true);
		if (translationFile != null) {
			return translationFile;
		}
		if (defaultLanguage.equals(language)) {
			throw new TechnicalException(String.format(
					"Cannot locate translation file for defaultLanguage=%s in filesystem", defaultLanguage));
		}
		log.warn("Cannot locate translations for language={}, use defaultLanguage={} instead", language, defaultLanguage);
		return getTranslationFile(translationsPath, defaultLanguage, defaultLanguage);
	}

	// expect translations to contain VERSION_INFO_PLACEHOLDER, so we can apply what we have injected via deployment
	private static String applyVersionInfo(String jsonStr, String versionInfo) {
		if (versionInfo != null) {
			jsonStr = jsonStr.replace(VERSION_INFO_PLACEHOLDER, versionInfo);
		}
		return jsonStr;
	}

	@SuppressWarnings("javasecurity:S6549") // the purpose of this method is to validate filePath from user controlled data
	private static File getSanitizedFile(String directoryPath, String filePath, boolean tryOnly) {
		var directory = new File(directoryPath);
		var fileUnsafe = new File(directory, filePath);
		try {
			// directoryContains checks existence too, but we want a different error message for this potential misconfiguration
			if (!fileUnsafe.exists()) {
				if (tryOnly) {
					log.debug("Access to nonexistent file={} with path={} in directory={} will be denied",
							filePath, fileUnsafe.getAbsolutePath(), directoryPath);
					return null;
				}
				throw new RequestDeniedException(
						String.format("Access to nonexistent file=%s with path=%s in directory=%s denied",
						filePath, fileUnsafe.getAbsolutePath(), directoryPath));
			}
			if (FileUtils.directoryContains(directory, fileUnsafe)) {
				return fileUnsafe;
			}
			if (tryOnly) {
				log.debug("Access to file={} with path={} outside of directory={} will be denied",
						filePath, fileUnsafe.getAbsolutePath(), directoryPath);
				return null;
			}
			// probably a directory traversal attempt
			throw new RequestDeniedException(
					String.format("Access to file=%s with path=%s outside of directory=%s denied",
					filePath, fileUnsafe.getAbsolutePath(), directoryPath));
		}
		catch (IOException e) {
			throw new RequestDeniedException(
					String.format("Access to file=%s with path=%s in directory=%s denied with error=%s",
					filePath, fileUnsafe.getAbsolutePath(), directoryPath, e.getMessage()));
		}
	}

}
