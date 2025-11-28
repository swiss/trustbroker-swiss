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
import java.io.IOException;
import java.nio.file.Path;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import swiss.trustbroker.common.exception.TechnicalException;

@Slf4j
public class DirectoryUtil {

	public void backupDirectory(String current, String backup) {
		backupDirectory(new File(current), new File(backup));
	}

	public void backupDirectory(File current, File backup) {
		if (current.exists()) {
			log.debug("Backing up current={} to backup={}", current, backup);
			deleteDirectory(backup); // just in case it failed last time
			renameDirectory(current, backup);
		}
		else {
			log.debug("No current={}", current);
		}
	}

	public void restoreBackup(String current, String backup) {
		restoreBackup(new File(current), new File(backup));
	}

	public void restoreBackup(File current, File backup) {
		if (!backup.exists()) {
			log.debug("No existing backup={}", backup);
			return;
		}
		if (current.exists()) {
			log.debug("Already existing current={}", current);
			deleteDirectory(current);
		}
		log.debug("Restore current={} from backup={}", current, backup);
		renameDirectory(backup, current);
	}

	public void deleteDirectory(String dirForDelete) {
		var dir = new File(dirForDelete);
		deleteDirectory(dir);

	}

	public void deleteDirectory(File dir) {
		try {
			if (dir.exists()) {
				FileUtils.deleteDirectory(dir);
				log.info("Deleted directory={} successfully", dir);
			}
			else {
				log.debug("No directory={}", dir);
			}
		}
		catch (IOException e) {
			log.error("File={} delete error: ", dir, e);
		}
	}

	public boolean renameDirectory(String curDirName, String newDirName) {
		var curDir = new File(curDirName);
		var newDir = new File(newDirName);
		return renameDirectory(curDir, newDir);
	}

	public boolean renameDirectory(File curDir, File newDir) {
		if (curDir.exists()) {
			if (curDir.renameTo(newDir)) {
				log.info("Rename current={} to new={} successfully", curDir.getAbsolutePath(), newDir.getAbsolutePath());
				return true;
			}
			else {
				log.error("Rename current={} to new={} failed", curDir.getAbsolutePath(), newDir.getAbsolutePath());
				return false;
			}
		}
		else {
			log.info("Rename current={} ignored (did not exists or already gone)", curDir.getAbsolutePath());
			return false;
		}
	}

	public boolean directoryExists(String directoryPath) {
		var directory = new File(directoryPath);
		return directory.exists();
	}

	public void createDirectoryIfNotExisting(File file, String purpose) {
		var parentDir = new File(file.getParent());
		if (!parentDir.exists()) {
			boolean dirCreated = parentDir.mkdirs();
			if (!dirCreated) {
				throw new TechnicalException(String.format("Could not create directory=%s for %s", parentDir, purpose));
			}
		}
	}

	public void copyDir(String sourceDirectoryLocation, String destinationDirectoryLocation) {
		var sourceDirectory = new File(sourceDirectoryLocation);
		var destinationDirectory = new File(destinationDirectoryLocation);
		try {
			FileUtils.copyDirectory(sourceDirectory, destinationDirectory);
			var msg = String.format("Activated new configuration by copying %s to %s", sourceDirectory, destinationDirectory);
			log.info(msg);
		}
		catch (IOException e) {
			var msg = String.format("Error while trying to copy from:%s to %s : %s",
					sourceDirectory.getAbsolutePath(), destinationDirectory.getAbsolutePath(), e.getMessage());
			throw new TechnicalException(msg);
		}
	}

	public static Path relativePath(Path file, Path basePath, boolean tryOnly) {
		try {
			var relative = basePath.relativize(file);
			if (relative.startsWith("../")) {
				if (tryOnly) {
					return null;
				}
				throw new TechnicalException(String.format("file=%s not relative to basePath=%s", file, basePath));
			}
			return relative;
		}
		catch (IllegalArgumentException ex) {
			if (tryOnly) {
				return null;
			}
			throw new TechnicalException(String.format("file=%s cannot be relativized to basePath=%s", file, basePath));
		}
	}

	public static boolean contentDiffers(File file1, File file2) {
		try {
			var equals = FileUtils.contentEquals(file1, file2);
			return !equals;
		}
		catch (IOException e) {
			log.error("Reading files for update error", e);
		}
		return false;
	}

	public static boolean existsOnFilesystemOrClasspath(String keystorePath) {
		var file = new File(keystorePath);
		if (file.exists()) {
			return true;
		}
		var url = DirectoryUtil.class.getClassLoader().getResource(keystorePath);
		return url != null;
	}
}
