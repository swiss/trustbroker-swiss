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

import { HttpErrorResponse, HttpResponse } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Params, Router } from '@angular/router';

import { DeviceInfoService } from '../services/deviceinfo.service';
import { ValidationService } from '../services/validation-service';

@Component({
	selector: 'app-device-info',
	templateUrl: './device-info.component.html',
	styleUrls: ['./device-info.component.scss'],
	standalone: false
})
export class DeviceInfoComponent implements OnInit {
	constructor(
		private readonly deviceInfoService: DeviceInfoService,
		private readonly validation: ValidationService,
		private readonly route: ActivatedRoute,
		private readonly router: Router
	) {}

	ngOnInit(): void {
		this.route.params.subscribe((params: Params) => {
			const cpUrn = this.validation.getValidParameter(params, 'cpUrn', ValidationService.ID, '');
			const rpUrn = this.validation.getValidParameter(params, 'rpUrn', ValidationService.ID, '');
			const id = this.validation.getValidParameter(params, 'id', ValidationService.ID, '');
			this.deviceInfoService.sendDeviceInfo(cpUrn, rpUrn, id).subscribe({
				next: resp => {
					this.handleDeviceInfoResponse(resp);
				},
				error: (errorResponse: HttpErrorResponse) => {
					if (errorResponse.status === 500) {
						void this.router.navigate(['/failure']);
					}
					if (errorResponse.status === 403) {
						window.location.href = `home/${rpUrn}/${id}`;
					}
				}
			});
		});
	}

	private handleDeviceInfoResponse(resp: HttpResponse<string>): void {
		// document.write for error page does not work here
		const url = resp?.url.replace(/^.*(\/failure\/.*$)/, '$1');
		if (url !== resp?.url) {
			void this.router.navigate([url]);
			return;
		}
		if (resp?.body?.includes('redirectUrl')) {
			const profile = JSON.parse(resp.body);
			void this.router.navigate([profile.redirectUrl]);
			return;
		}
		window.document.write(resp?.body);
		if (document.forms.length > 0) {
			document.forms.item(0).submit();
		} else {
			void this.router.navigate(['/failure']);
		}
	}
}
