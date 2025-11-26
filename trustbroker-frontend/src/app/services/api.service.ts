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
import { EMPTY, Observable, catchError, switchMap, tap, throwError } from 'rxjs';

import { environment } from '../../environments/environment';
import { Configuration } from '../model/Configuration';
import { SsoParticipants } from '../model/SsoParticipants';
import { SupportInfo } from '../model/SupportInfo';
import { Theme } from '../model/Theme';
import { EncodeUtil } from '../shared/encode-util';

@Injectable({
	providedIn: 'root'
})
export class ApiService {
	private readonly baseUrl = environment.apiUrl;
	private configuration: Configuration | undefined;

	constructor(private readonly http: HttpClient) {}

	getIdpObjects(issuer: string, authnRequestId: string): Observable<HttpResponse<string>> {
		return this.http.get(`${this.baseUrl}hrd/relyingparties/${issuer}/tiles?session=${authnRequestId}`, {
			headers: new HttpHeaders().set('Accept', 'text/html,application/json'),
			observe: 'response',
			responseType: 'text'
		});
	}

	// btoa support just from IE10
	selectIdp(authnRequestId: string, urn: string): Observable<HttpResponse<string>> {
		urn = btoa(urn).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
		return this.http.get<string>(`${this.baseUrl}hrd/claimsproviders/${urn}?session=${authnRequestId}`, {
			headers: new HttpHeaders().set('Accept', 'text/html'),
			observe: 'response',
			responseType: 'text' as 'json'
		});
	}

	continueResponseToRp(sessionId: string) {
		// top level navigation, the response is the SAML response form
		window.location.href = `${this.baseUrl}hrd/relyingparties/${sessionId}/continue`;
	}

	relogin(sessionId: string) {
		// top level navigation, the response is the SAML request form to CP or HRD screen
		window.location.href = `${this.baseUrl}hrd/${sessionId}/continue`;
	}

	fetchSupportInfo(errorCode: string, sessionId: string) {
		return this.http.get<SupportInfo>(`${this.baseUrl}support/${errorCode}/${sessionId}`);
	}

	getSsoParticipants(ssoGroupName: string): Observable<SsoParticipants[]> {
		return ssoGroupName
			? this.http.get<SsoParticipants[]>(`${this.baseUrl}sso/participants/${ssoGroupName}`)
			: this.http.get<SsoParticipants[]>(`${this.baseUrl}sso/participants`);
	}

	logoutSingleActiveGroup(logoutIssuer: string): Observable<SsoParticipants[]> {
		return this.http.delete<SsoParticipants[]>(`${this.baseUrl}sso/rp/${logoutIssuer}`);
	}

	logoutSsoParticipant(ssoGroupName: string, relyingPartyId: string, claimsPartyId: string, subjectNameId: string): Observable<HttpResponse<string>> {
		const rpId = EncodeUtil.base64UrlEncodeNoPadding(relyingPartyId);
		const cpId = EncodeUtil.base64UrlEncodeNoPadding(claimsPartyId);
		const subjId = EncodeUtil.base64UrlEncodeNoPadding(subjectNameId);
		return this.http.delete<string>(`${this.baseUrl}sso/group/${ssoGroupName}/${rpId}/${cpId}/${subjId}`, {
			headers: new HttpHeaders().set('Accept', 'text/html'),
			observe: 'response',
			responseType: 'text' as 'json'
		});
	}

	public initializeConfiguration(): Observable<never> {
		return this.http.get<Configuration>(`${this.baseUrl}config/frontend`).pipe(
			catchError(error => {
				console.error('Failed to load configuration', error);
				return throwError(() => error);
			}),
			tap(configuration => (this.configuration = configuration)),
			switchMap(() => EMPTY)
		);
	}

	getImageUrl(theme: Theme, image: string) {
		return `${this.baseUrl}hrd/assets/images/${theme.name}/${image}`;
	}

	getConfiguration(): Configuration {
		if (this.configuration === undefined) {
			console.error('Configuration is not loaded!');
		}
		return this.configuration;
	}
}
