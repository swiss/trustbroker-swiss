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

import { HttpClient, HttpResponse, provideHttpClient } from '@angular/common/http';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { TranslateLoader, TranslateModule } from '@ngx-translate/core';
import { of } from 'rxjs';
import { anything, mock, when } from 'ts-mockito';

import { TranslationService } from '../app.module';
import { HelpPanelComponent } from './help-panel.component';
import { ApiService } from '../services/api.service';
import { SafeMarkupPipe } from '../pipes/safe-markup.pipe';
import { MatExpansionModule } from '@angular/material/expansion';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

describe('HelpPanelComponent', () => {
	let component: HelpPanelComponent;
	let fixture: ComponentFixture<HelpPanelComponent>;
	let mockApiService: ApiService;

	beforeEach(async () => {
		await TestBed.configureTestingModule({
			declarations: [HelpPanelComponent, SafeMarkupPipe],
			imports: [
				MatExpansionModule,
				TranslateModule.forRoot({
					loader: {
						provide: TranslateLoader,
						useClass: TranslationService,
						deps: [HttpClient]
					}
				})
			],
			providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([]), provideNoopAnimations()]
		}).compileComponents();
	});

	beforeEach(() => {
		// mock services
		mockApiService = mock(ApiService);
		when(mockApiService.getIdpObjects(anything(), anything())).thenReturn(of(new HttpResponse<string>({ body: '' })));
		TestBed.configureTestingModule({
			providers: [{ provide: ApiService, useValue: mockApiService }]
		});

		fixture = TestBed.createComponent(HelpPanelComponent);
		component = fixture.componentInstance;
		fixture.detectChanges();
	});

	it('should create', () => {
		expect(component).toBeTruthy();
	});
});
