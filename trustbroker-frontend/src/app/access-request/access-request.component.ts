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

import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Params } from '@angular/router';

import { ValidationService } from '../services/validation-service';
import { environment } from '../../environments/environment';

@Component({
	selector: 'app-access-request',
	templateUrl: './access-request.component.html',
	styleUrls: ['./access-request.component.scss'],
	standalone: false
})
export class AccessRequestComponent implements OnInit {
	private readonly baseUrl = environment.apiUrl;
	private sessionId: string;
	private _state: string;
	private _showContinueButton: boolean;
	private _showAbortButton: boolean;
	private _showLoginButton: boolean;

	constructor(
		private readonly route: ActivatedRoute,
		private readonly validation: ValidationService
	) {}

	get showContinueButton(): boolean {
		return this._showContinueButton;
	}

	get showAbortButton(): boolean {
		return this._showAbortButton;
	}

	get showLoginButton(): boolean {
		return this._showLoginButton;
	}

	get infoKey(): string {
		return `trustbroker.accessrequest.message.${this._state}`;
	}

	ngOnInit(): void {
		this.route.params.subscribe((params: Params) => {
			this.sessionId = this.validation.getValidParameter(params, 'sessionId', ValidationService.ID, '');
			this._state = this.validation.getValidParameter(params, 'state', ValidationService.TEXT_KEY, '');
			this._showContinueButton = this._state === 'initiate';
			this._showAbortButton = this._state === 'initiate' || this._state === 'abort';
			this._showLoginButton = this._state === 'confirm';
		});
	}

	initiateAccessRequest() {
		window.location.href = `${this.baseUrl}accessrequest/initiate/${this.sessionId}`;
	}

	abortAccessRequest() {
		window.location.href = `${this.baseUrl}accessrequest/abort/${this.sessionId}`;
	}

	completeAccessRequest() {
		window.location.href = `${this.baseUrl}accessrequest/complete/${this.sessionId}`;
	}
}
