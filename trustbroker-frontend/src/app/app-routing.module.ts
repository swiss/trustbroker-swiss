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

import { Routes } from '@angular/router';

import { AccessRequestComponent } from './access-request/access-request.component';
import { DeviceInfoComponent } from './device-info/device-info.component';
import { ErrorPageComponent } from './error-page/error-page.component';
import { HrdCardsComponent } from './hrd-cards/hrd-cards.component';
import { ProfileSelectionComponent } from './profile-selection/profile-selection.component';
import { SsoComponent } from './sso/sso.component';
import { HrdCardsContainerComponent } from './hrd-cards-container/hrd-cards-container.component';

export const routes: Routes = [
	{
		path: 'home/:issuer/:authnRequestId',
		component: HrdCardsContainerComponent,
		data: { pageTitle: 'trustbroker.hrd.page.title' }
	},
	{
		path: 'device/:cpUrn/:rpUrn/:id',
		component: DeviceInfoComponent
	},
	{
		path: '',
		component: HrdCardsComponent
	},
	{
		path: 'sso',
		component: SsoComponent
	},
	{
		path: 'sso/:ssoGroupName',
		component: SsoComponent
	},
	{
		path: 'sso/:silent/:issuer/:ignored',
		component: SsoComponent
	},
	{
		path: 'accessrequest/:sessionId/:state',
		component: AccessRequestComponent
	},
	{
		path: 'profile/selection/:id',
		component: ProfileSelectionComponent
	},
	{
		path: 'profile/:id',
		component: ProfileSelectionComponent
	},
	{
		path: 'announcements/:issuer/:authnRequestId',
		loadComponent: () => import('./announcements/announcements.component')
	},
	{
		path: 'announcements/:issuer/:authnRequestId/:appName',
		loadComponent: () => import('./announcements/announcements.component')
	},
	{
		path: 'failure/:textKey/:reference',
		component: ErrorPageComponent
	},
	{
		path: 'failure/:textKey/:reference/:unknown',
		component: ErrorPageComponent
	},
	{
		path: 'failure/:textKey/:reference/:sessionId/:button',
		component: ErrorPageComponent
	},
	{
		path: 'failure/:textKey',
		component: ErrorPageComponent
	},
	{
		path: 'failure',
		component: ErrorPageComponent
	},
	{
		path: '**',
		component: ErrorPageComponent
	}
];
