/**
 * FreeRDP: A Remote Desktop Protocol Client
 * Kerberos Auth Protocol
 *
 * Copyright 2015 ANSSI, Author Thomas Calderon
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "kerberos.h"

#include <winpr/stream.h>
#include <winpr/crt.h>

#include <stdarg.h>
#include <gssapi/gssapi.h>

int
convert_spn_to_gss_service_name(char *server, gss_name_t * name)
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_msg_buffer;

	input_msg_buffer.value = server;
	input_msg_buffer.length = strlen(input_msg_buffer.value) + 1;

	maj_stat = gss_import_name(&min_stat, &input_msg_buffer, GSS_C_NT_HOSTBASED_SERVICE, name);

	if (GSS_ERROR(maj_stat))
	{
		WLog_ERR(TAG, "error: gss_import_name failed\n");
		return 0;
	}
	/* DEBUG: We could display friendly name using gss_display_name */
	/* Do not call gss_release_buffer on input_msg_buffer, it is done in the upper layer */
	return 1;
}

int
call_gss_wrap(gss_ctx_id_t ctx, PSecBuffer in, PSecBuffer out)
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input;
	gss_buffer_desc output;
	int state;

#ifdef WITH_DEBUG_NEGO
	WLog_ERR(TAG, "call_gss_wrap\n");
#endif

	input.value = in->pvBuffer;
	input.length = in->cbBuffer;

	maj_stat = gss_wrap(&min_stat, ctx, TRUE, GSS_C_QOP_DEFAULT, &input, &state, &output);
	if (GSS_ERROR(maj_stat))
	{
		WLog_ERR(TAG, "error: gss_wrap failed\n");
		return 0;
	}
	if (state == 0)
	{
		WLog_ERR(TAG, "error: gss_wrap OK, but Encryption and Integrity are disabled\n");
		(void) gss_release_buffer(&min_stat, &output);
		return 0;
	}
	CopyMemory(out->pvBuffer, output.value, output.length);

	(void) gss_release_buffer(&min_stat, &output);

	return 1;
}

int
call_gss_unwrap(gss_ctx_id_t ctx, PSecBuffer in, PSecBuffer out)
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input;
	gss_buffer_desc output;
	int state;

#ifdef WITH_DEBUG_NEGO
	WLog_ERR(TAG, "call_gss_unwrap\n");
#endif

	input.value = in->pvBuffer;
	input.length = in->cbBuffer;

	maj_stat = gss_unwrap(&min_stat, ctx, &input, &output, &state, NULL);
	if (GSS_ERROR(maj_stat))
	{
		WLog_ERR(TAG, "error: gss_unwrap failed\n");
		return 0;
	}
	if (state == 0)
	{
		WLog_ERR(TAG, "error: gss_unwrap OK, but Encryption and Integrity are disabled\n");
		(void) gss_release_buffer(&min_stat, &output);
		return 0;
	}

	CopyMemory(out->pvBuffer, output.value, output.length);

	(void) gss_release_buffer(&min_stat, &output);

	return 1;
}
