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

package swiss.trustbroker.script.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.InputStreamReader;
import javax.script.Compilable;
import javax.script.CompiledScript;
import javax.script.ScriptException;

import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.common.exception.TechnicalException;

@Slf4j
public class ScriptSource {

	private String scriptName;

	public ScriptSource(String scriptName) {
		this.scriptName = scriptName;
	}

	public CompiledScript loadScript(Compilable compilingEngine) {
		try (var scriptStream = loadScriptFromFileSystemOrClasspath(scriptName)) {
			var ret = compileScript(compilingEngine, scriptStream);
			log.debug("Loaded script {}", scriptName);
			return ret;
		}
		catch (Exception ex) {
			log.error("Failed loading script {}: {}", scriptName, ex.getMessage(), ex);
		}
		return null;
	}

	private static InputStream loadScriptFromFileSystemOrClasspath(String scriptName) throws FileNotFoundException {
		InputStream stream;
		var scriptFile = new File(scriptName);
		if (scriptFile.exists()) {
			stream = new FileInputStream(scriptFile);
		}
		else {
			stream = ScriptSource.class.getClassLoader().getResourceAsStream(scriptName);
		}

		// fallback for testing in development, to call groovy scripts we deliber
		if (stream == null) {
			throw new IllegalArgumentException("Cannot locate resource "
					+ scriptName + " in filesystem or on classpath, working dir: " + (new File(".")).getAbsolutePath());
		}
		return stream;
	}

	private static CompiledScript compileScript(Compilable compilingEngine, InputStream stream)	throws TechnicalException {
		try {
			return compilingEngine.compile(new InputStreamReader(stream));
		}
		catch (ScriptException e) {
			throw new TechnicalException(String.format("Failed to evaluate script.  Details: %s", e), e);
		}
	}

}
