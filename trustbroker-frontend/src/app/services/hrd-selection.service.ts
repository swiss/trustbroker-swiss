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
import { DestroyRef, Injectable, inject } from '@angular/core';
import { ApiService } from './api.service';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { IdpObject } from '../model/IdpObject';

@Injectable({ providedIn: 'root' })
export class HrdSelectionService {
	private readonly apiService = inject(ApiService);
	private readonly destroyRef = inject(DestroyRef);

	public selectIdp(authnRequestId: string, { urn }: IdpObject): void {
		this.apiService
			.selectIdp(authnRequestId, urn)
			.pipe(takeUntilDestroyed(this.destroyRef))
			.subscribe({
				next: response => this.apiService.handleFormResponse(response),
				error: errorResponse => {
					console.error('an error occurred', errorResponse);
				}
			});
	}
}
