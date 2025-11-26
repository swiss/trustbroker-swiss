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

export class EncodeUtil {
	public static base64UrlEncodeNoPadding(data: string): string {
		if (data === null || data.length === 0) {
			return '';
		}
		try {
			// apparently this causes "maximum call stack size exceeded error" with large strings, but outs is of limited length
			let result = window.btoa(data);
			// replace characters for URL encoding, remove padding
			result = result.replace(/[+]/g, '-').replace(/\//g, '_').replace(/=/g, '');
			// NOSONAR
			// console.debug('[EncodeUtil] Encoded fingerprint:', result);
			return result;
		} catch (_ex) {
			// NOSONAR
			// console.debug('[EncodeUtil] Could not encode fingerprint', _ex);
			return '';
		}
	}

	public static arrayBufferToString(data: ArrayBuffer): string {
		return String.fromCharCode.apply(null, new Uint8Array(data));
	}
}
