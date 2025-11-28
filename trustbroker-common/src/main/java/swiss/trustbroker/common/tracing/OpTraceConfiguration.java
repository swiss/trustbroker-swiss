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

package swiss.trustbroker.common.tracing;

import java.io.BufferedReader;
import java.io.FileReader;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Data
public final class OpTraceConfiguration {

	private static final RequestContextFactory REQ_CTX_FACTORY = new DefaultRequestContextFactory();

	// hex formatted trace format version number
	private static final int OPTRACE_VERSION = 3;

	private static final String OPTRACE_LOGGER_NAME
			= System.getProperty(OpTraceConfiguration.class.getName() + "logger.name", "swiss.trustbroker.op");

	private static final String PKG_NAME
			= System.getProperty(OpTraceConfiguration.class.getName() + "package.name", "");

	private static final String PKG_VERSION
			= System.getProperty(OpTraceConfiguration.class.getName() + "package.version", "");

	private static final String INSTANCE_NAME
			= System.getProperty(OpTraceConfiguration.class.getName() + "instance.name", getHostName());

	private OpTraceConfiguration() {
	}

	public static RequestContextFactory getRequestContextFactory() {
		return REQ_CTX_FACTORY;
	}

	public static int getOptraceVersion() {
		return OPTRACE_VERSION;
	}

	public static String getLoggerName() {
		return OPTRACE_LOGGER_NAME;
	}

	public static String getInstanceName() {
		return INSTANCE_NAME;
	}

	public static String getPkgName() {
		return PKG_NAME;
	}

	public static String getPkgVersion() {
		return PKG_VERSION;
	}

	// best effort on unix based systems
	private static String getHostName() {
		try (var reader = new BufferedReader(new FileReader("/etc/hostname"))) {
			return reader.readLine()
						 .strip();
		}
		catch (Exception e) {
			return "no-hostname";
		}
	}

}
