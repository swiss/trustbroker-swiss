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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import swiss.trustbroker.common.exception.TechnicalException;

@SpringBootTest
@ContextConfiguration(classes = { DirectoryUtil.class })
class DirectoryUtilTest {

	@Autowired
	DirectoryUtil directoryUtil;

	private static File tempDir;

	@BeforeAll
	static void setUp() throws IOException {
		tempDir = Files.createTempDirectory("DirectoryUtilTest").toFile();
	}

	@AfterAll
	static void tearDown() throws IOException {
		if (tempDir != null) {
			FileUtils.deleteDirectory(tempDir);
		}
	}

	@Test
	void backupDirectory() {
		var oldDir = existingDir(tempDir, "bak");
		var newDir = existingDir(tempDir, "new");
		existingDir(newDir, "sub");
		directoryUtil.backupDirectory(newDir.getAbsoluteFile(), oldDir.getAbsoluteFile());
		assertTrue(oldDir.exists());
		assertFalse(newDir.exists());
		assertTrue(new File(oldDir, "sub").exists());
	}

	@Test
	void restoreBackup() throws IOException  {
		var oldDir = existingDir(tempDir, "bak");
		var subDir = existingDir(oldDir, "sub"); // moved to new
		var newDir = missingDir(tempDir, "new");
		var subDirNew = missingDir(newDir, "sub");
		directoryUtil.restoreBackup(newDir.getAbsoluteFile(), oldDir.getAbsoluteFile());
		assertFalse(oldDir.exists());
		assertTrue(newDir.exists());
		assertFalse(subDir.exists());
		assertTrue(subDirNew.exists());
	}

	@Test
	void restoreBackupDeleteCurrent() throws IOException  {
		var oldDir = existingDir(tempDir, "bak");
		var subDir = existingDir(oldDir, "sub"); // moved to new
		var newDir = existingDir(tempDir, "new");
		var subDirNew = missingDir(newDir, "sub");
		var subToClean = existingDir(newDir, "clean"); // deleted
		directoryUtil.restoreBackup(newDir, oldDir);
		assertFalse(oldDir.exists());
		assertFalse(subToClean.exists());
		assertFalse(subDir.exists());
		assertTrue(newDir.exists());
		assertTrue(subDirNew.exists());
	}

	@Test
	void restoreMissingBackup() throws IOException  {
		var oldDir = missingDir(tempDir, "bak");
		var newDir = existingDir(tempDir, "new");
		var subDir = existingDir(newDir, "sub"); // retained
		directoryUtil.restoreBackup(newDir, oldDir);
		assertFalse(oldDir.exists());
		assertTrue(newDir.exists());
		assertTrue(subDir.exists());
	}

	@ParameterizedTest
	@MethodSource
	void relativePath(Path path, Path base, Path expected) {
		assertThat(DirectoryUtil.relativePath(path, base, true), is(expected));
	}

	static Object[][] relativePath() {
		return new Object[][] {
				{ Path.of("/base/sub/dir"), Path.of("/base"), Path.of("sub/dir") },
				{ Path.of("/base/sub/dir"), Path.of("/base/sub"), Path.of("dir") },
				{ Path.of("/base/sub/dir"), Path.of("/other"), null },
				{ Path.of("/base/sub/dir"), Path.of("/base/sub/other"), null },
		};
	}

	@Test
	void relativePathThrows() {
		var file = Path.of("/test/path");
		var basePath = Path.of("/test/other");
		assertThrows(TechnicalException.class,
				() -> DirectoryUtil.relativePath(file, basePath,false));
	}

	@Test
	void testExistsOnFilesystemOrClasspath() {
		assertTrue(DirectoryUtil.existsOnFilesystemOrClasspath("private.txt"));
		assertTrue(DirectoryUtil.existsOnFilesystemOrClasspath(
				getClass().getClassLoader().getResource("private.txt").getFile()));
		assertFalse(DirectoryUtil.existsOnFilesystemOrClasspath("invalid.txt"));
	}

	@Test
	void testContentDiffers() {
		var file1 = new File(DirectoryUtilTest.class.getClassLoader().getResource("private.txt").getFile());
		var file2 = new File(DirectoryUtilTest.class.getClassLoader().getResource("assets/test/test.txt").getFile());
		var invalid = new File("invalid.txt");
		assertTrue(DirectoryUtil.contentDiffers(file1, file2));
		assertFalse(DirectoryUtil.contentDiffers(file1, file1));
		assertTrue(DirectoryUtil.contentDiffers(file1, invalid));
		assertFalse(DirectoryUtil.contentDiffers(invalid, invalid));
	}

	@Test
	void testRenameDir() {
		var dir = existingDir(tempDir, "sub1");
		var toDir = new File(tempDir, "sub2");
		assertTrue(directoryUtil.renameDirectory(dir.getAbsoluteFile(), toDir.getAbsoluteFile()));
		assertFalse(dir.exists());
		assertTrue(toDir.exists());
		assertFalse(directoryUtil.renameDirectory(dir.getAbsoluteFile(), toDir.getAbsoluteFile()));
	}

	@Test
	void testCreateDirectoryIfNotExisting() throws Exception {
		var dir = missingDir(tempDir, "create");
		// parent exists
		directoryUtil.createDirectoryIfNotExisting(dir, "test");
		assertFalse(dir.exists());
		// parent created
		directoryUtil.createDirectoryIfNotExisting(new File(dir, "test.txt"), "test");
		assertTrue(dir.exists());
	}

	@Test
	void testCopyDir() throws Exception {
		var from = existingDir(tempDir, "source");
		var sub = existingDir(from, "sub1");
		var to = missingDir(tempDir, "target");
		var toSub = missingDir(to, "sub1");
		directoryUtil.copyDir(from.getAbsolutePath(), to.getAbsolutePath());
		assertTrue(sub.exists());
		assertTrue(toSub.exists());
	}

	private File existingDir(File parent, String name) {
		var subDir = new File(parent, name);
		subDir.mkdirs();
		return subDir;
	}

	private File missingDir(File parent, String name) throws IOException {
		var subDir = new File(parent, name);
		FileUtils.deleteDirectory(subDir);
		return subDir;
	}
}
