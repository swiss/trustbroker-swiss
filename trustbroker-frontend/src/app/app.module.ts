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

import { LayoutModule } from '@angular/cdk/layout';
import { NgModule, inject, provideAppInitializer } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { DateAdapter, NativeDateAdapter } from '@angular/material/core';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatGridListModule } from '@angular/material/grid-list';
import { MatIconModule, MatIconRegistry } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSidenavModule } from '@angular/material/sidenav';
import { BrowserModule } from '@angular/platform-browser';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { RouterModule } from '@angular/router';
import {
	HTTP_INTERCEPTORS,
	HttpEvent,
	HttpHandler,
	HttpHeaders,
	HttpInterceptor,
	HttpRequest,
	HttpResponse,
	provideHttpClient,
	withInterceptorsFromDi
} from '@angular/common/http';
import { MissingTranslationHandler, MissingTranslationHandlerParams, TranslateModule } from '@ngx-translate/core';
import { Observable, of } from 'rxjs';
import {
	ObAlertModule,
	ObButtonModule,
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
import { DisabledCardComponent } from './hrd-cards/disabled-card/disabled-card.component';
import { HrdCardsComponent } from './hrd-cards/hrd-cards.component';
import { SmallCardComponent } from './hrd-cards/small-card/small-card.component';
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
import { HrdCardsV2Component } from './hrd-cards-v2/hrd-cards-v2.component';
import { AnyCardHasCategoryPipe } from './pipes/any-card-has-category.pipe';
import { BucketizeIdpObjectsPipe } from './pipes/bucketize-idp-objects.pipe';
import { HrdBannerComponent } from './hrd-banner/hrd-banner.component';
import { HasTranslationPipe } from './pipes/has-translation.pipe';
import { ThemeSelectorComponent } from './theme-selector/theme-selector';
import { ApiService } from './services/api.service';

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

/**
 * Workaround for Oblique: Oblique loads two files for every language: oblique-<lang>.json and <lang.json>.
 * The paths are currently defined in oblique itself and cannot be configured.
 * To be able to still use the available paths serviced by the trustbroker's backend, we are
 * - muting the files oblique-<lang>.json and changing the paths
 * - changing the url of the <lang>.json
 */
class LangHttpInterceptor implements HttpInterceptor {
	intercept(req: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
		if (/\/oblique-.{2}.json$/.test(req.url)) {
			return of(this.responseWith(req.url, '{}'));
		}

		const matchResult = /\/assets\/i18n\/(?<lang>.{2}).json$/.exec(req.url);
		if (matchResult?.groups['lang']) {
			return next.handle(req.clone({ url: `/api/v1/hrd/translations/${matchResult.groups['lang']}` }));
		}

		return next.handle(req);
	}

	private responseWith(url: string, body: unknown): HttpResponse<unknown> {
		return new HttpResponse<unknown>({
			body,
			status: 200,
			statusText: 'ok',
			url,
			headers: new HttpHeaders({
				'Content-Type': 'application/json; charset=utf-8',
				Date: new Date().toISOString()
			})
		});
	}
}

@NgModule({
	declarations: [
		AppComponent,
		HrdCardsContainerComponent,
		HrdCardsComponent,
		HrdCardsV2Component,
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
		SmallCardComponent,
		AccessRequestComponent,
		DisabledCardComponent,
		BackdropComponent,
		ThemeSelectorComponent
	],
	bootstrap: [AppComponent],
	imports: [
		BrowserModule,
		BrowserAnimationsModule,
		MatCardModule,
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
		AnyCardHasCategoryPipe,
		BucketizeIdpObjectsPipe,
		HasTranslationPipe,
		ObButtonModule
	],
	providers: [
		provideObliqueConfiguration({
			accessibilityStatement: {
				applicationName: "Replace me with the application's name",
				conformity: 'none',
				applicationOperator: 'Replace me with the name and address of the federal office that exploit this application, HTML is permitted',
				contact: { /* at least 1 email or phone number has to be provided */ emails: [''], phones: [''] }
			},
			translate: {
				config: {
					missingTranslationHandler: {
						provide: MissingTranslationHandler,
						useClass: MissingTranslationHelper
					}
				}
			}
		}),
		LanguageService,
		ThemeService,
		ValidationService,
		DeviceInfoService,
		{ provide: HTTP_INTERCEPTORS, useClass: CustomHttpInterceptor, multi: true },
		{ provide: HTTP_INTERCEPTORS, useClass: LangHttpInterceptor, multi: true },
		{ provide: HTTP_INTERCEPTORS, useClass: ObHttpApiInterceptor, multi: true },
		{ provide: ObMasterLayoutConfig, useClass: MasterLayoutConfig },
		{ provide: DateAdapter, useClass: NativeDateAdapter },
		provideHttpClient(withInterceptorsFromDi()),
		provideAppInitializer(() => inject(ApiService).initializeConfiguration())
	]
})
export class AppModule {
	constructor(iconRegistry: MatIconRegistry) {
		// Font Awesome as default
		iconRegistry.setDefaultFontSetClass('fas');
	}
}
