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

import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Params, Router } from '@angular/router';

import { Profile } from '../model/Profile';
import { ProfileService } from '../services/profile.service';
import { ProfileRequest } from '../services/profile-request';
import { ProfileResponse } from '../services/profile-response';
import { ValidationService } from '../services/validation-service';

@Component({
	selector: 'app-profile-selection',
	templateUrl: './profile-selection.component.html',
	styleUrls: ['./profile-selection.component.scss'],
	standalone: false
})
export class ProfileSelectionComponent implements OnInit {
	readonly APPLICATIONS_PER_PROFILE = 5;
	profileResponse: ProfileResponse;
	profiles: Profile[];
	stateId: string;

	constructor(
		private readonly profileService: ProfileService,
		private readonly validation: ValidationService,
		private readonly route: ActivatedRoute,
		private readonly router: Router
	) {}

	ngOnInit(): void {
		this.route.params.subscribe((params: Params) => {
			const id = this.validation.getValidParameter(params, 'id', ValidationService.ID, '');
			this.profileService.getProfiles(id).subscribe({
				next: resp => {
					this.profileResponse = resp;
					this.profiles = this.profileResponse.profiles;
					this.stateId = id;
				},
				error: (/* _errorResponse: HttpErrorResponse */) => {
					void this.router.navigate(['/failure']);
				}
			});
		});
	}

	onClick(profileId: string) {
		const input: ProfileRequest = this.createProfileRequest(this.stateId, profileId);
		this.profileService.sendSelectedProfile(input).subscribe({
			next: resp => {
				// Access Request GET URL from automatically followed redirect, document.write does not work here
				let url = resp.url.replace(/^.*(\/accessrequest\/.*$)/, '$1');
				if (url !== resp.url) {
					void this.router.navigate([url]);
					return;
				}
				// document.write for error page does not work here
				url = resp.url.replace(/^.*(\/failure\/.*$)/, '$1');
				if (url !== resp.url) {
					void this.router.navigate([url]);
					return;
				}
				window.document.write(resp.body);
				if (document.forms.length > 0) {
					document.forms.item(0).submit();
				} else {
					void this.router.navigate(['/failure']);
				}
			},
			error: (errorResponse: HttpErrorResponse) => {
				if (errorResponse.status === 500) {
					void this.router.navigate(['/failure']);
				}
			}
		});
	}

	private createProfileRequest(stateId: string, profileId: string): ProfileRequest {
		return {
			stateId,
			profileId
		};
	}
}
