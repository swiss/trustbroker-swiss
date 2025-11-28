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

import { Params } from '@angular/router';

export class ValidationService {
	public static TEXT_KEY = '^[0-9A-Za-z]*$';

	public static ID = '^[0-9A-Za-z_.-]*$';

	public getValidParameter(params: Params, key: string, pattern: string, defaultValue: string): string {
		const value = params[key];
		if (!!value && !value.match(pattern)) {
			console.error('Invalid value for parameter:', key);
			return defaultValue;
		}
		return value;
	}
}
