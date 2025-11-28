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

/**
 * A base config class that mau contain references relative to its file path.
 * <br/>
 * General resolution order:
 * <ol>
 *     <li>Name relative to the subfolder of the file that defines the <code>ReferenceHolder</code>.</li>
 *     <li>Name relative to the global directory of the referenced type.
 *         <ul>
 *             <li>For scripts <code>definition/scripts</code> configured in <code>globalScriptPath</code>.</li>
 *             <li>For profiles <code>definition/profiles</code> configured in <code>globalProfilesPath</code>.</li>
 *             <li>For certificates <code>keystore</code> appending the subfolder.</li>
 *         </ul>
 *     </li>
 *     <li>Name relative to the top directory of the referenced type.
 *         <ul>
 *             <li>For scripts <code>definition</code>.</li>
 *             <li>For profiles <code>definition</code>.</li>
 *             <li>For certificates <code>keystore</code>.</li>
 *         </ul>
 *      </li>
 * </ol>
 *
 * E.g.
 * Suppose <code>definition/test/app/SetupRP_Test.xml</code> references a script named <code>hooks/Test.groovy</code>.
 * This is searched in the following order:
 * <ol>
 *     <li><code>definition/test/app/hooks/Test.groovy</code></li>
 *     <li><code>definition/scripts/hooks/Test.groovy</code></li>
 *     <li><code>definition/hooks/Test.groovy</code></li>
 * </ol>
 * Suppose it also references a certificate named <code>service/keystore.pem</code>.
 * This is searched in the following order:
 * <ol>
 *     <li><code>definition/test/app/service/keystore.pem</code></li>
 *     <li><code>keystore/test/app/service/keystore.pem</code></li>
 *     <li><code>keystore/service/keystore.pem</code></li>
 * </ol>
 * Suppose it also references a profile named <code>base/ProfileRP_Test.xml</code>.
 * This is searched in the following order:
 * <ol>
 *     <li><code>definition/test/app/base/ProfileRP_Test.xml</code></li>
 *     <li><code>definition/profiles/base/ProfileRP_Test.xml</code></li>
 *     <li><code>definition/base/ProfileRP_Test.xml</code></li>
 * </ol>
 *
 * @since 1.7.0
 */
public interface PathReference {

	/**
	 * @return The file's path relative to the definition directory.
	 */
	public String getSubPath();

	/**
	 * @param subPath The file's path relative to the definition directory.
	 */
	public void setSubPath(String subPath);

}
