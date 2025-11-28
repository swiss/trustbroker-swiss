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
import { Injectable } from '@angular/core';
import { CookieService as NxCookieService } from 'ngx-cookie-service';
import { CookieConfiguration } from '../model/CookieConfiguration';

@Injectable({
	providedIn: 'root'
})
export class CookieService {
	constructor(private readonly nxCookieService: NxCookieService) {}

	public set(configuration: CookieConfiguration, value: string, expiresIsoDate?: string): void {
		this.nxCookieService.set(configuration.name, value, {
			expires: expiresIsoDate ? new Date(expiresIsoDate) : this.secondsToDays(configuration.maxAge),
			secure: configuration.secure,
			sameSite: configuration.sameSite,
			path: configuration.path,
			domain: configuration.domain
		});
	}

	public check(name: string): boolean {
		return this.nxCookieService.check(name);
	}

	public get(name: string): string {
		return this.nxCookieService.get(name);
	}

	public delete(name: string, path?: string): void {
		this.nxCookieService.delete(name, path);
	}

	private secondsToDays(seconds?: number): number | undefined {
		return seconds ? seconds / 24 / 3_600 : undefined;
	}
}
