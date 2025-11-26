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

import { LanguageCode } from './enums/LanguageCode';

export const Constant = {
	CountryCodeSwitzerland: 'ch',
	DefaultLanguageCode: LanguageCode.en,
	LanguageCodes: [LanguageCode.de, LanguageCode.fr, LanguageCode.it, LanguageCode.en],
	LanguageDisplayLabels: {
		[LanguageCode.de]: 'DE',
		[LanguageCode.fr]: 'FR',
		[LanguageCode.it]: 'IT',
		[LanguageCode.en]: 'EN'
	},

	NativeLanguageDisplayLabels: {
		[LanguageCode.de]: 'Deutsch',
		[LanguageCode.fr]: 'Français',
		[LanguageCode.it]: 'Italiano',
		[LanguageCode.en]: 'English'
	},

	PRIMENG_LIST_ROW_HEIGHT: 33,
	PRIMENG_LIST_BORDER_HEIGHT: 1,

	// regex patterns
	IsoDatePattern: '^\\d{4}-\\d{2}-\\d{2}$',
	UiDatePattern: '^\\d{2}[.]\\d{2}[.]\\d{4}',

	// The format date string are returned from the BE if they don't contain time information only day, in case of
	// time information is also included, the format is yyyy-MM-dd'T'HH:mm:ss'Z
	RestApiDayFormat: 'YYYY-MM-DD',

	PhoneNumberCountryCode: '0041',
	PhoneNumberPatternInternational: '^00( ?\\d){8,}$',
	PhoneNumberIllegalSwissNationalDestinationCodes: [80, 84, 86, 87, 90, 98, 99],

	// starts with [_A-Za-z0-9-+] (cannot start with a dot)
	// next part can contain dot(s) and min 1 max 61 chars after dot but that is optional
	// first two part max length = 61 char, followed by a '@'
	// the after @ part is basically the same but only alphanumeric char allowed immediately after @
	// and generally no '+' or '_'. Min 1 max 61 char.
	// then a '.' and a min 2 max 61 long alphabetic TLD are mandatory
	// + and * are replaced with {1,61} and {0,61} because of Sonar
	EmailPattern:
		'(^[_A-Za-z0-9-+]{1,61}(\\.[_A-Za-z0-9-+]{1,61}){0,61}){1,61}@(([A-Za-z0-9]{1,61})([A-Za-z0-9-]{0,61})' +
		'(\\.[A-Za-z0-9-]{1,61}){0,61}){1,61}(\\.[A-Za-z]{2,61})$',
	NumberPattern: /^\d+$/,

	// 2015-1-11 13:57
	// 2015-1-11T13:57
	DateTimePattern: '^\\d\\d\\d\\d-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[T ]([0-2][0-9]|1[0-9]|2[0-3]):([0-5][0-9]|[0-5][0-9])$',

	// various http constants
	CrnkContentType: 'application/vnd.api+json',
	JsonContentType: 'application/json',
	CsrfTokenHeader: 'X-XSRF-TOKEN',
	Empty: 'empty',

	TranslationMaxLength: 2000,
	PostCodePattern: {
		af: {
			regexp: '^[0-9]{4}$',
			label: '9999'
		}
	}
};
