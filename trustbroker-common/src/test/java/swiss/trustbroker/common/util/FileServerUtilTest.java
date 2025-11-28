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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.MediaType;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class FileServerUtilTest {

	private static final String ASSETS = "assets";

	private static final String TRANSLATIONS = "translations";

	@Test
	void readFileContentValid() {
		var directory = SamlTestBase.fileFromClassPath(ASSETS).getAbsolutePath();
		var result = FileServerUtil.readFileContent(directory, "test/test.txt", MediaType.TEXT_PLAIN_VALUE);
		assertThat(result.name(), is(directory + File.separatorChar + "test" + File.separatorChar + "test.txt"));
		assertThat(result.contentType(), is(MediaType.TEXT_PLAIN_VALUE));
		assertThat(new String(result.data(), StandardCharsets.UTF_8), is("""
				Test
				"""));
	}

	@Test
	void readFileContentDetection() {
		var directory = SamlTestBase.fileFromClassPath(ASSETS).getAbsolutePath();
		var result = FileServerUtil.readFileContent(directory, "test/test.svg", null);
		assertThat(result.name(), is(directory + File.separatorChar + "test" + File.separatorChar + "test.svg"));
		assertThat(result.contentType(), is("image/svg+xml"));
		assertThat(new String(result.data(), StandardCharsets.UTF_8), is("""
				<svg>
				</svg>
				"""));
	}

	@Test
	void readFileContentBlocked() {
		var directory = SamlTestBase.fileFromClassPath(ASSETS).getAbsolutePath();
		// invalid path traversal
		assertThrows(RequestDeniedException.class,
				() -> FileServerUtil.readFileContent(directory,"../private.txt", MediaType.TEXT_PLAIN_VALUE));
	}

	@Test
	void readTranslationFile() {
		var directory = SamlTestBase.fileFromClassPath(TRANSLATIONS).getAbsolutePath();
		var result = FileServerUtil.readTranslationFile(directory, "de", "en", "42.0");
		assertThat(result.name(), is(directory + File.separatorChar + "de.json"));
		assertThat(result.contentType(), is(MediaType.APPLICATION_JSON_VALUE));
		assertThat(new String(result.data(), StandardCharsets.UTF_8), is("""
				{
					"language": "Deutsch",
					"version": "XTB/42.0"
				}
				"""));
	}

	@Test
	void readTranslationFileDefaultLanguage() {
		var directory = SamlTestBase.fileFromClassPath(TRANSLATIONS).getAbsolutePath();
		var result = FileServerUtil.readTranslationFile(directory, "fr", "en", "TrustBroker/B1.2");
		assertThat(result.name(), is(directory + File.separatorChar + "en.json"));
		assertThat(result.contentType(), is(MediaType.APPLICATION_JSON_VALUE));
		assertThat(new String(result.data(), StandardCharsets.UTF_8), is("""
				{
					"language": "English",
					"version": "XTB/TrustBroker/B1.2"
				}
				"""));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"../assets/it",
			"../assets/en"
	})
	void readTranslationFileBlocked(String language) {
		var directory = SamlTestBase.fileFromClassPath(TRANSLATIONS).getAbsolutePath();
		// file exists, but invalid path traversal -> default language is used
		var result = FileServerUtil.readTranslationFile(directory, language, "en", null);
		assertThat(result.name(), is(directory + File.separatorChar + "en.json"));
		assertThat(result.contentType(), is(MediaType.APPLICATION_JSON_VALUE));
		assertThat(new String(result.data(), StandardCharsets.UTF_8), is("""
				{
					"language": "English",
					"version": "XTB/VERSION@STAGE"
				}
				"""));
	}

}
