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

package swiss.trustbroker.common.tracing;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

public class OpTraceResponseWrapper extends HttpServletResponseWrapper
{
	private int status = HttpServletResponse.SC_OK;

	public OpTraceResponseWrapper(HttpServletResponse response)
	{
		super(response);
	}

	@Override
	public void setStatus(int sc) {
    	status = sc;
        super.setStatus(sc);
    }

	@Override
    public void sendRedirect(String name) throws IOException {
    	status = HttpServletResponse.SC_MOVED_TEMPORARILY;
        super.sendRedirect(name);
    }

	@Override
    public void sendError(int cd, String msg) throws IOException {
    	status = cd;
        super.sendError(cd, msg);
    }

	@Override
    public void sendError(int cd) throws IOException {
    	status = cd;
        super.sendError(cd);
    }

	@Override
    public int getStatus() {
        return status;
    }

}
