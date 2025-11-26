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

import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { mergeMap } from 'rxjs/operators';

import { DeviceInfoService } from './deviceinfo.service';

@Injectable()
export class CustomHttpInterceptor implements HttpInterceptor {
	constructor(private readonly deviceInfoService: DeviceInfoService) {}

	intercept(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
		return this.deviceInfoService.generateDeviceToken().pipe(mergeMap(deviceId => this.addDeviceIdHeader(request, next, deviceId)));
	}

	private addDeviceIdHeader(request: HttpRequest<unknown>, next: HttpHandler, deviceId: string): Observable<HttpEvent<unknown>> {
		request = request.clone({ headers: request.headers.append('X-DevId', deviceId) });
		return next.handle(request);
	}
}
