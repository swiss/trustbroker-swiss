/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

import { HttpClient, HttpHeaders, HttpResponse } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, from } from 'rxjs';

import { environment } from '../../environments/environment';
import { DeviceInfoResponse } from '../model/DeviceInfoResponse';
import { map } from 'rxjs/operators';
import { Md5 } from 'ts-md5';

@Injectable()
export class DeviceInfoService {
	private readonly apiBaseUrl = environment.apiUrl;
	private readonly deviceInfoUrl = `${this.apiBaseUrl}device/info`;
	private readonly permissionsNames = [
		'accelerometer',
		'ambient-light-sensor',
		'background-fetch',
		'background-sync',
		'bluetooth',
		'camera',
		'clipboard-read',
		'clipboard-write',
		'device-info',
		'display-capture',
		'geolocation',
		'gyroscope',
		'magnetometer',
		'microphone',
		'midi',
		'nfc',
		'notifications',
		'persistent-storage',
		'push',
		'speaker'
	];

	constructor(private readonly http: HttpClient) {}

	sendDeviceInfo(cpUrn: string, rpUrn: string, id: string): Observable<HttpResponse<string>> {
		return this.postDeviceInfo(cpUrn, rpUrn, id);
	}

	generateDeviceToken(): Observable<string> {
		const fingerprint = [window.navigator.userAgent, String(new Date().getTimezoneOffset()), ...this.fingerprintRenderingContext()];

		return this.generatePermissions().pipe(
			map(permissions => {
				const part1 = fingerprint;
				const part2 = [...fingerprint, ...permissions];
				// NOSONAR
				// console.debug('Device info token', { part1, part2});
				return [part1, part2]
					.map(eachPart => eachPart.join('|'))
					.map(eachPartAsString => Md5.hashStr(eachPartAsString))
					.join('.');
			})
		);
	}

	private generatePermissions(): Observable<string[]> {
		const permissions = Promise.all(this.fingerprintPermissions()).catch(() => {
			// NOSONAR
			// console.debug('[DeviceInfoService] Could not build fingerprint', ex);
			return [''];
		});
		return from(permissions);
	}

	private fingerprintPermissions(): Promise<string>[] {
		try {
			if (!window.navigator.permissions) {
				// NOSONAR
				// console.debug('[DeviceInfoService] window.navigator.permissions not available');
				return [Promise.resolve('noperm')];
			}
			return this.permissionsNames.map(name => this.getPermission(name as PermissionName));
		} catch (_ex) {
			// NOSONAR
			// console.debug('[DeviceInfoService] Could not fingerprint permissions', _ex);
			return [Promise.resolve('failedperm')];
		}
	}

	private getPermission(permissionName: PermissionName): Promise<string> {
		return (
			window.navigator.permissions
				.query({ name: permissionName })
				// permission not defined
				.catch(() => {
					// NOSONAR
					// console.debug('[DeviceInfoService] Could not get permission', permissionName, String(ex));
					return null;
				})
				.then(result => (result != null ? result.state : 'notfound'))
		);
	}

	private fingerprintRenderingContext(): string[] {
		try {
			const result: string[] = [];
			const canvas = this.createCanvas();
			// Firefox logs a warning in the console if we test this, hence not enabled:
			// var context2: WebGL2RenderingContext = canvas.getContext('webgl2');
			// result.push(Promise.resolve(String(context2 != null)));
			const context: WebGLRenderingContext | null = canvas.getContext('webgl');
			result.push(String(context != null));
			if (context != null) {
				result.push(String(context.VENDOR), String(context.RENDERER), String(context.SHADING_LANGUAGE_VERSION));
				if (typeof context.getContextAttributes === 'function') {
					const attributes = context.getContextAttributes();
					result.push(attributes ? String(attributes.antialias) : 'noctxattr');
				} else {
					result.push('noctxattr');
				}
				// could add more here, see e.g. https://browserleaks.com/webgl
			}
			return result;
		} catch (_ex) {
			// NOSONAR
			// console.debug('[DeviceInfoService] Could not fingerprint rendering context', _ex);
			return ['failedctx'];
		}
	}

	private createCanvas() {
		const canvas = document.createElement('canvas');
		canvas.width = 1;
		canvas.height = 1;
		return canvas;
	}

	private postDeviceInfo(cpUrn: string, rpUrn: string, id: string): Observable<HttpResponse<string>> {
		const deviceInfoRes = new DeviceInfoResponse();
		deviceInfoRes.cpUrn = cpUrn;
		deviceInfoRes.rpUrn = rpUrn;
		deviceInfoRes.id = id;
		return this.http.post<string>(`${this.deviceInfoUrl}`, deviceInfoRes, {
			headers: new HttpHeaders().set('Accept', 'text/html, application/json'),
			observe: 'response',
			responseType: 'text' as 'json'
		});
	}
}
