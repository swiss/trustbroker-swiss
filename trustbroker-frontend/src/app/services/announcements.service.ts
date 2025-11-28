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

import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { AnnouncementResponse } from './announcement-response';
import { environment } from '../../environments/environment';

@Injectable({
	providedIn: 'root'
})
export class AnnouncementsService {
	private readonly baseUrl = environment.apiUrl;

	constructor(private readonly http: HttpClient) {}

	getAnnouncements(issuer, appName): Observable<AnnouncementResponse[]> {
		if (typeof appName !== 'undefined') {
			return this.http.get<AnnouncementResponse[]>(`${this.baseUrl}announcements/${issuer}/${appName}`, {});
		}
		return this.http.get<AnnouncementResponse[]>(`${this.baseUrl}announcements/${issuer}`, {});
	}
}
