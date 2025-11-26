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

import { HttpClient, HttpHeaders, HttpResponse } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, from } from 'rxjs';

import { environment } from '../../environments/environment';
import { DeviceInfoResponse } from '../model/DeviceInfoResponse';
import { EncodeUtil } from '../shared/encode-util';

@Injectable()
export class DeviceInfoService {
	private readonly baseUrl = environment.apiUrl;
	private readonly deviceInfoUrl = `${this.baseUrl}device/info`;
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
		// these return just plain values wrapped in resolved Promises to unify handling
		const fingerprint = this.fingerprintUserAgent().concat(this.fingerprintTimezone()).concat(this.fingerprintRenderingContext());
		const part1 = Promise.all(fingerprint)
			.catch(() => {
				// NOSONAR
				// console.debug('[DeviceInfoService] Could not build fingerprint', ex);
				return [''];
			})
			.then(values => this.hash(values.join('|')));
		// these return actual Promises, result depending on document or iframe, that's why we send it as part2
		const permissions = fingerprint.concat(this.fingerprintPermissions());
		const part2 = Promise.all(permissions)
			.catch(() => {
				// NOSONAR
				// console.debug('[DeviceInfoService] Could not build fingerprint', ex);
				return [''];
			})
			.then(values => this.hash(values.join('|')));
		return from(Promise.all([part1, part2]).then(values => values.join('.')));
	}

	private fingerprintUserAgent(): Promise<string>[] {
		return [Promise.resolve(window.navigator.userAgent)];
	}

	private fingerprintTimezone(): Promise<string>[] {
		return [Promise.resolve(String(new Date().getTimezoneOffset()))];
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

	private fingerprintRenderingContext(): Promise<string>[] {
		try {
			const result: Promise<string>[] = [];
			const canvas = this.createCanvas();
			// Firefox logs a warning in the console if we test this, hence not enabled:
			// var context2: WebGL2RenderingContext = canvas.getContext('webgl2');
			// result.push(Promise.resolve(String(context2 != null)));
			const context: WebGLRenderingContext = canvas.getContext('webgl');
			result.push(Promise.resolve(String(context != null)));
			if (context != null) {
				result.push(Promise.resolve(String(context.VENDOR)));
				result.push(Promise.resolve(String(context.RENDERER)));
				result.push(Promise.resolve(String(context.SHADING_LANGUAGE_VERSION)));
				if (typeof context.getContextAttributes === 'function') {
					result.push(Promise.resolve(String(context.getContextAttributes().antialias)));
				} else {
					result.push(Promise.resolve('noctxattr'));
				}
				// could add more here, see e.g. https://browserleaks.com/webgl
			}
			return result;
		} catch (_ex) {
			// NOSONAR
			// console.debug('[DeviceInfoService] Could not fingerprint rendering context', _ex);
			return [Promise.resolve('failedctx')];
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

	private hash(value: string): Promise<string> {
		// empty fingerprint is rejected when comparing on server side, so browser not support SHA256 are not SSO
		try {
			if (!window.crypto?.subtle) {
				// NOSONAR
				// console.debug('[DeviceInfoService] Could not hash fingerprint, window.crypto.subtle not available');
				return Promise.resolve('');
			}
			// NOSONAR
			// console.debug('[DeviceInfoService] Fingerprint before hashing: ', value);
			// convert to UTF-8, hash, convert back
			const data = new TextEncoder().encode(value);
			return this.getSha256Hash(data);
		} catch (_ex) {
			// NOSONAR
			// console.debug('[DeviceInfoService] Could not hash fingerprint', _ex);
			return Promise.resolve('');
		}
	}

	private getSha256Hash(data: ArrayBuffer): Promise<string> {
		return window.crypto.subtle
			.digest('SHA-256', data)
			.catch(() => {
				// NOSONAR
				// console.debug('[DeviceInfoService] Could not calculate sha256 hash', ex);
				return new ArrayBuffer(0);
			})
			.then(result => EncodeUtil.base64UrlEncodeNoPadding(EncodeUtil.arrayBufferToString(result)));
	}
}
