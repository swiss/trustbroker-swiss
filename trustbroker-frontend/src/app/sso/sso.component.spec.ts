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

import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient } from '@angular/common/http';
import { SsoComponent } from './sso.component';
import { TranslateLoader, TranslateModule } from '@ngx-translate/core';
import { TranslationService } from '../app.module';
import { ApiService } from '../services/api.service';
import { anything, mock, when } from 'ts-mockito';
import { of } from 'rxjs';
import { SafeMarkupPipe } from '../pipes/safe-markup.pipe';
import { ThemeService } from '../services/theme-service';
import { ValidationService } from '../services/validation-service';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { RouterModule } from '@angular/router';

describe('SsoComponent', () => {
	let component: SsoComponent;
	let fixture: ComponentFixture<SsoComponent>;
	let mockApiService: ApiService;
	let mockValidationService: ValidationService;

	beforeEach(async () => {
		await TestBed.configureTestingModule({
			declarations: [SsoComponent, SafeMarkupPipe],
			imports: [
				TranslateModule.forRoot({
					loader: {
						provide: TranslateLoader,
						useClass: TranslationService,
						deps: [HttpClient]
					}
				}),
				RouterModule.forRoot([])
			],
			providers: [provideHttpClient(), provideHttpClientTesting()]
		}).compileComponents();
	});

	beforeEach(() => {
		// mock services
		mockApiService = mock(ApiService);
		when(mockApiService.getSsoParticipants(anything())).thenReturn(of([]));
		mockValidationService = mock(ValidationService);
		when(mockValidationService.getValidParameter(anything(), anything(), anything(), anything())).thenReturn('param');
		const mockThemeService = mock(ThemeService);
		TestBed.configureTestingModule({
			providers: [
				{ provide: ApiService, useValue: mockApiService },
				{ provide: ThemeService, useValue: mockThemeService },
				{ provide: ValidationService, useValue: mockValidationService }
			]
		});

		fixture = TestBed.createComponent(SsoComponent);
		component = fixture.componentInstance;
		fixture.detectChanges();
	});

	it('should create', () => {
		expect(component).toBeTruthy();
	});
});
