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
import { Observable } from 'rxjs';

import { environment } from '../../environments/environment';
import { ProfileRequest } from './profile-request';
import { ProfileResponse } from './profile-response';

@Injectable({
	providedIn: 'root'
})
export class ProfileService {
	private readonly baseUrl = environment.apiUrl;

	constructor(private readonly http: HttpClient) {}

	getProfiles(id: string): Observable<ProfileResponse> {
		const headers = new Headers();
		headers.append('XTB-ProfileId', id);
		return this.http.get<ProfileResponse>(`${this.baseUrl}hrd/profiles`, {
			headers: new HttpHeaders().set('XTB-ProfileId', id)
		});
	}

	sendSelectedProfile(profileRequest: ProfileRequest): Observable<HttpResponse<string>> {
		return this.http.post<string>(`${this.baseUrl}hrd/profile`, profileRequest, {
			headers: new HttpHeaders().set('Accept', 'text/html'),
			observe: 'response',
			responseType: 'text' as 'json'
		});
	}
}
