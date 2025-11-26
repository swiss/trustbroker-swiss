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

import { Pipe, PipeTransform, SecurityContext } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

// Uses DomSanitizer to sanitize texts while supporting a few additional markdown notations.
// This pipe must be used solely on translations obtained from the XTB API, not on user input!
// While DomSanitizer removes scripts elements and event handlers, and marks script links 'unsafe',
// it allows links to arbitrary websites - this must not be controlled by user input.
// Example use:
// <p [innerHTML]="'label' | translate | safeMarkup"></p>
// Markdown support:
// - newline: \r\n \r \n
// - links: [label](url) [label](target|url)
@Pipe({
	name: 'safeMarkup',
	standalone: false
})
export class SafeMarkupPipe implements PipeTransform {
	constructor(private readonly sanitizer: DomSanitizer) {}

	transform(text: string | null): SafeHtml {
		// Replace markdown with HTML before sanitizing:
		// \r\n \r \n => <br/>
		let result = text?.replace(/\r\n|\r|\n|<br\s*\/?>/g, '<br/>');
		// [label](url) [label](target|url) => <a target="..." href="...">...</a>
		// eslint complains about the \| escape
		// eslint-disable-next-line no-useless-escape
		result = result?.replace(/\[([^\]]+)\]\((?:([a-zA-Z0-9_]+)\|)?(([^\)]+))\)/g, '<a target="$2" href="$3">$1</a>');
		// sanitize result:
		result = this.sanitizer.sanitize(SecurityContext.HTML, result);
		// NOSONAR
		// if (result !== text) {
		//	console.debug('[SafeMarkupPipe] Original:', text);
		//	console.debug('[SafeMarkupPipe] Cleaned:', result);
		// }
		return result;
	}
}
