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

import { LayoutModule } from '@angular/cdk/layout';
import { NgModule, inject, provideAppInitializer } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { DateAdapter, NativeDateAdapter } from '@angular/material/core';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatGridListModule } from '@angular/material/grid-list';
import { MatIconModule, MatIconRegistry } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSidenavModule } from '@angular/material/sidenav';
import { BrowserModule } from '@angular/platform-browser';
import { RouterModule } from '@angular/router';
import { HTTP_INTERCEPTORS, HttpClient, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { MissingTranslationHandler, MissingTranslationHandlerParams, TranslateLoader, TranslateModule, TranslationObject } from '@ngx-translate/core';
import { Observable } from 'rxjs';
import {
	ObAlertModule,
	ObButtonModule,
	ObDocumentMetaModule,
	ObDocumentMetaService,
	ObHttpApiInterceptor,
	ObMasterLayoutConfig,
	ObMasterLayoutModule,
	ObPopoverModule,
	provideObliqueConfiguration
} from '@oblique/oblique';

import { AccessRequestComponent } from './access-request/access-request.component';
import { AppComponent } from './app.component';
import { routes } from './app-routing.module';
import { BackdropComponent } from './backdrop/backdrop.component';
import { DeviceInfoComponent } from './device-info/device-info.component';
import { ErrorBoxComponent } from './error-page/error-box/error-box.component';
import { ErrorPageComponent } from './error-page/error-page.component';
import { HelpPanelComponent } from './help-panel/help-panel.component';
import { HrdCardsComponent } from './hrd-cards/hrd-cards.component';
import { MasterLayoutConfig } from './material-frame/config/master-layout-config';
import { MaterialFooterComponent } from './material-frame/material-footer/material-footer.component';
import { MaterialFrameComponent } from './material-frame/material-frame.component';
import { MaterialHeaderComponent } from './material-frame/material-header/material-header.component';
import { EnvironmentDisplayPipe } from './pipes/environment-display.pipe';
import { LanguageDisplayPipe } from './pipes/language-display.pipe';
import { NativeLanguageDisplayPipe } from './pipes/native-language-display.pipe';
import { SafeMarkupPipe } from './pipes/safe-markup.pipe';
import { ProfileSelectionComponent } from './profile-selection/profile-selection.component';
import { CustomHttpInterceptor } from './services/custom-http-interceptor.service';
import { DeviceInfoService } from './services/deviceinfo.service';
import { LanguageService } from './services/language.service';
import { ThemeService } from './services/theme-service';
import { ValidationService } from './services/validation-service';
import { SsoComponent } from './sso/sso.component';
import { HrdCardsContainerComponent } from './hrd-cards-container/hrd-cards-container.component';
import { BucketizeIdpObjectsPipe } from './pipes/bucketize-idp-objects.pipe';
import { HrdBannerComponent } from './hrd-banner/hrd-banner.component';
import { HasTranslationPipe } from './pipes/has-translation.pipe';
import { ThemeSelectorComponent } from './theme-selector/theme-selector';
import { ApiService } from './services/api.service';
import { environment } from '../environments/environment';

export class MissingTranslationHelper implements MissingTranslationHandler {
	handle(params: MissingTranslationHandlerParams): string {
		if (params.interpolateParams) {
			// eslint workaround: as it is an Object we cannot use dot-notation
			const value = 'Default';
			return params.interpolateParams[value] || params.key;
		}
		return params.key;
	}
}

export class BTBTranslateLoader extends TranslateLoader {
	private readonly httpClient = inject(HttpClient);

	override getTranslation(lang: string): Observable<TranslationObject> {
		return this.httpClient.get<TranslationObject>(`${environment.apiUrl}ui/translations/${lang}`);
	}
}

@NgModule({
	declarations: [
		AppComponent,
		HrdCardsContainerComponent,
		HrdCardsComponent,
		HrdBannerComponent,
		SsoComponent,
		MaterialFooterComponent,
		MaterialFrameComponent,
		MaterialHeaderComponent,
		NativeLanguageDisplayPipe,
		LanguageDisplayPipe,
		EnvironmentDisplayPipe,
		SafeMarkupPipe,
		DeviceInfoComponent,
		ErrorBoxComponent,
		ErrorPageComponent,
		HelpPanelComponent,
		ProfileSelectionComponent,
		AccessRequestComponent,
		BackdropComponent,
		ThemeSelectorComponent
	],
	bootstrap: [AppComponent],
	imports: [
		BrowserModule,

		MatGridListModule,
		MatMenuModule,
		MatIconModule,
		MatButtonModule,
		MatProgressSpinnerModule,
		LayoutModule,
		TranslateModule,
		ObMasterLayoutModule,
		ObAlertModule,
		RouterModule.forRoot(routes),
		ObPopoverModule,
		MatSidenavModule,
		MatCheckboxModule,
		FormsModule,
		MatExpansionModule,
		BucketizeIdpObjectsPipe,
		HasTranslationPipe,
		ObButtonModule,
		ObDocumentMetaModule
	],
	providers: [
		provideObliqueConfiguration({
			accessibilityStatement: {
				createdOn: new Date('2026-01-06'),
				applicationName: "Replace me with the application's name",
				conformity: 'none',
				applicationOperator: 'Replace me with the name and address of the federal office that exploit this application, HTML is permitted',
				contact: [{ phone: '' }, { email: '' }]
			},
			translate: {
				additionalFiles: [], // avoid downloading <lang>.json, oblique by defaule uses oblique-<lang>.json
				config: {
					missingTranslationHandler: {
						provide: MissingTranslationHandler,
						useClass: MissingTranslationHelper
					},
					loader: {
						provide: TranslateLoader,
						useClass: BTBTranslateLoader,
						deps: [HttpClient]
					}
				}
			}
		}),
		LanguageService,
		ThemeService,
		ValidationService,
		DeviceInfoService,
		{ provide: HTTP_INTERCEPTORS, useClass: CustomHttpInterceptor, multi: true },
		{ provide: HTTP_INTERCEPTORS, useClass: ObHttpApiInterceptor, multi: true },
		{ provide: ObMasterLayoutConfig, useClass: MasterLayoutConfig },
		{ provide: DateAdapter, useClass: NativeDateAdapter },
		provideHttpClient(withInterceptorsFromDi()),
		provideAppInitializer(() => inject(ApiService).initializeConfiguration())
	]
})
export class AppModule {
	private readonly metaService = inject(ObDocumentMetaService);

	constructor(iconRegistry: MatIconRegistry) {
		// Font Awesome as default
		iconRegistry.setDefaultFontSetClass('fas');
		this.metaService.titleSuffix = 'trustbroker.app.page.title';
	}
}
