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
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_SSPI_KERBEROS_PRIVATE_H
#define FREERDP_SSPI_KERBEROS_PRIVATE_H

#include <winpr/sspi.h>
#include <winpr/windows.h>

#include "../sspi.h"
#include "../../log.h"

struct _KRB_CONTEXT
{
	CtxtHandle context;
	SSPI_CREDENTIALS* credentials;
	SEC_WINNT_AUTH_IDENTITY identity;

	/* GSSAPI */
	UINT32 major_status;
	UINT32 minor_status;
	UINT32 actual_time;
	sspi_gss_cred_id_t cred;
	sspi_gss_ctx_id_t gss_ctx;
	sspi_gss_name_t target_name;
};
typedef struct _KRB_CONTEXT KRB_CONTEXT;

void krb_ContextFree(KRB_CONTEXT* context);

#endif /* FREERDP_SSPI_KERBEROS_PRIVATE_H */
