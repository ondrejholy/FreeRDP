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
#define TAG WINPR_TAG("sspi.Kerberos")

#include <gssapi/gssapi.h>

struct _KRB_CONTEXT
{
	SEC_WINNT_AUTH_IDENTITY identity;
	CtxtHandle context;
	SSPI_CREDENTIALS *credentials;

	//GSSAPI stuff
	gss_name_t target_name;
	OM_uint32 major_status, minor_status;
	OM_uint32 actual_time;
	gss_cred_id_t cred;
	gss_ctx_id_t gss_ctx;
};
typedef struct _KRB_CONTEXT KRB_CONTEXT;

void krb_ContextFree(KRB_CONTEXT * krb_ctx);

#endif /* FREERDP_SSPI_KERBEROS_PRIVATE_H */
