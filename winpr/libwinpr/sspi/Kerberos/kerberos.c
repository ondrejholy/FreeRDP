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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <winpr/crt.h>
#include <winpr/sspi.h>
#include <winpr/print.h>
#include <winpr/sysinfo.h>
#include <winpr/registry.h>

#include "kerberos.h"
#include "kerberos_gss.h"

#include "../sspi.h"


char *KRB_PACKAGE_NAME = "Kerberos";

static gss_OID_desc _gss_spnego_krb5_mechanism_oid_desc =
	{ 9, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" };

KRB_CONTEXT *
kerberos_ContextNew()
{
	KRB_CONTEXT *context;
	context = (KRB_CONTEXT *) calloc(1, sizeof(KRB_CONTEXT));

	if (!context)
		return NULL;

	context->minor_status = 0;
	context->major_status = 0;

	context->gss_ctx = GSS_C_NO_CONTEXT;
	context->cred = GSS_C_NO_CREDENTIAL;

	return context;
}

void
kerberos_ContextFree(KRB_CONTEXT * krb_ctx)
{
	if (krb_ctx != NULL)
	{
		/* FIXME: should probably free some GSSAPI stuff */
		free(krb_ctx);
	}
}

SECURITY_STATUS SEC_ENTRY
kerberos_AcquireCredentialsHandleW(SEC_WCHAR * pszPrincipal, SEC_WCHAR * pszPackage,
				   ULONG fCredentialUse, void *pvLogonID, void *pAuthData,
				   SEC_GET_KEY_FN pGetKeyFn, void *pvGetKeyArgument,
				   PCredHandle phCredential, PTimeStamp ptsExpiry)
{
	return SEC_E_OK;
}

SECURITY_STATUS SEC_ENTRY
kerberos_AcquireCredentialsHandleA(SEC_CHAR * pszPrincipal, SEC_CHAR * pszPackage,
				   ULONG fCredentialUse, void *pvLogonID, void *pAuthData,
				   SEC_GET_KEY_FN pGetKeyFn, void *pvGetKeyArgument,
				   PCredHandle phCredential, PTimeStamp ptsExpiry)
{
	return SEC_E_OK;
}

SECURITY_STATUS SEC_ENTRY
kerberos_FreeCredentialsHandle(PCredHandle phCredential)
{
	SSPI_CREDENTIALS *credentials;

	if (!phCredential)
		return SEC_E_INVALID_HANDLE;

	credentials = (SSPI_CREDENTIALS *) sspi_SecureHandleGetLowerPointer(phCredential);

	if (!credentials)
		return SEC_E_INVALID_HANDLE;

	sspi_CredentialsFree(credentials);
	return SEC_E_OK;
}

SECURITY_STATUS SEC_ENTRY
kerberos_QueryCredentialsAttributesW(PCredHandle phCredential, ULONG ulAttribute, void *pBuffer)
{
#ifdef WITH_DEBUG_NEGO
	printf("DEBUG: kerberos_QueryCredentialsAttributesW\n");
#endif
	if (ulAttribute == SECPKG_CRED_ATTR_NAMES)
	{
		return SEC_E_OK;
	}

	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY
kerberos_QueryCredentialsAttributesA(PCredHandle phCredential, ULONG ulAttribute, void *pBuffer)
{
#ifdef WITH_DEBUG_NEGO
	printf("DEBUG: kerberos_QueryCredentialsAttributesA\n");
#endif
	return kerberos_QueryCredentialsAttributesW(phCredential, ulAttribute, pBuffer);
}

SECURITY_STATUS SEC_ENTRY
kerberos_InitializeSecurityContextW(PCredHandle phCredential, PCtxtHandle phContext,
				    SEC_WCHAR * pszTargetName, ULONG fContextReq, ULONG Reserved1,
				    ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2,
				    PCtxtHandle phNewContext, PSecBufferDesc pOutput,
				    ULONG * pfContextAttr, PTimeStamp ptsExpiry)
{
#ifdef WITH_DEBUG_NEGO
	printf("debug: kerberos_InitializeSecurityContextW\n");
#endif

	printf("debug: kerberos_InitializeSecurityContextW is not implemented\n");
	return SEC_E_UNSUPPORTED_FUNCTION;
}

int
kerberos_SetContextServicePrincipalNameA(KRB_CONTEXT * context, SEC_CHAR * ServicePrincipalName)
{
	char *replacedSPN = NULL;
	char *toreplace = NULL;
	size_t length;
	if (!ServicePrincipalName)
	{
		context->target_name = NULL;
		return 1;
	}
	/* GSSAPI expects a SPN of type <service>@FQDN, let's construct it */
	length = strlen(ServicePrincipalName);
	replacedSPN = malloc(length);
	if (replacedSPN == NULL)
	{
		WLog_ERR(TAG, "Kerberos: Could not allocate memory.\n");
		return -1;
	}
	memcpy(replacedSPN, ServicePrincipalName, length);
	toreplace = strchr(replacedSPN, '/');
	*toreplace = '@';
	if (!convert_spn_to_gss_service_name(replacedSPN, &(context->target_name)))
	{
		WLog_ERR(TAG, "Kerberos: Failed to get target service name.\n");
		free(replacedSPN);
		return -1;
	}
	free(replacedSPN);
	return 1;
}


SECURITY_STATUS SEC_ENTRY
kerberos_InitializeSecurityContextA(PCredHandle phCredential, PCtxtHandle phContext,
				    SEC_CHAR * pszTargetName, ULONG fContextReq, ULONG Reserved1,
				    ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2,
				    PCtxtHandle phNewContext, PSecBufferDesc pOutput,
				    ULONG * pfContextAttr, PTimeStamp ptsExpiry)
{
	KRB_CONTEXT *context;
	SSPI_CREDENTIALS *credentials;
	PSecBuffer input_buffer = NULL;
	PSecBuffer output_buffer = NULL;
	context = (KRB_CONTEXT *) sspi_SecureHandleGetLowerPointer(phContext);

	//GSSAPI stuff
	gss_buffer_desc input_tok, output_tok;
	gss_OID actual_mech;
	gss_OID desired_mech = &_gss_spnego_krb5_mechanism_oid_desc;
	OM_uint32 actual_services;
	input_tok.length = 0;
	output_tok.length = 0;


#ifdef WITH_DEBUG_NEGO
	printf("debug: kerberos_InitializeSecurityContextA\n");
#endif

	if (!context)
	{
		context = kerberos_ContextNew();

		if (!context)
			return SEC_E_INSUFFICIENT_MEMORY;

		if (fContextReq & ISC_REQ_CONFIDENTIALITY)
		{
#ifdef WITH_DEBUG_NEGO
			printf("kerberos_InitializeSecurityContextA, ISC_REQ_CONFIDENTIALITY is set\n");
#endif
		}

		credentials = (SSPI_CREDENTIALS *) sspi_SecureHandleGetLowerPointer(phCredential);
		context->credentials = credentials;

#ifdef WITH_DEBUG_NEGO
		printf("kerberos_InitializeSecurityContextA, target %s\n", pszTargetName);
#endif
		if (kerberos_SetContextServicePrincipalNameA(context, pszTargetName) < 0)
			return SEC_E_INTERNAL_ERROR;

		sspi_SecureHandleSetLowerPointer(phNewContext, context);
		sspi_SecureHandleSetUpperPointer(phNewContext, (void *) KRB_PACKAGE_NAME);
	}
	if (!pInput)
	{
		int i = 0;

		context->major_status = gss_init_sec_context(&(context->minor_status),
							     context->cred,
							     &(context->gss_ctx),
							     context->target_name,
							     desired_mech,
							     GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG,
							     GSS_C_INDEFINITE,
							     GSS_C_NO_CHANNEL_BINDINGS,
							     &input_tok,
							     &actual_mech,
							     &output_tok, &actual_services,
							     &(context->actual_time));
		if (GSS_ERROR(context->major_status))
		{
			if (i == 0)
				WLog_ERR(TAG, "Kerberos: Initialize failed, do you have correct kerberos tgt initialized ?\n");
			else
				WLog_ERR(TAG, "Kerberos: Negotiation failed.\n");

			WLog_ERR(TAG, "Kerberos: gss_init_sec_context failed with %lu\n", GSS_C_GSS_CODE);
			/*
			cssp_gss_report_error(GSS_C_GSS_CODE, "Kerberos: SPNEGO negotiation failed.",
					      context->major_status, context->minor_status);
			*/
			return -1;
		}
#ifdef WITH_DEBUG_NEGO
		printf("######## output_tok.length = %lu\n", output_tok.length);
#endif
		if (context->major_status & GSS_S_CONTINUE_NEEDED)
		{
			//Store information in context, output buffer an return SEC_I_CONTINUE_NEEDED
			if (output_tok.length != 0)
			{
				//Copy in output buffer

				if (!pOutput)
					return SEC_E_INVALID_TOKEN;

				if (pOutput->cBuffers < 1)
					return SEC_E_INVALID_TOKEN;

				output_buffer = sspi_FindSecBuffer(pOutput, SECBUFFER_TOKEN);

				if (!output_buffer)
					return SEC_E_INVALID_TOKEN;

				if (output_buffer->cbBuffer < 1)
					return SEC_E_INVALID_TOKEN;

				CopyMemory(output_buffer->pvBuffer, output_tok.value,
					   output_tok.length);
				output_buffer->cbBuffer = output_tok.length;
				//Release allocated memory
				(void) gss_release_buffer(&(context->minor_status), &output_tok);
				return SEC_I_CONTINUE_NEEDED;
			}
		}
	}
	else
	{
		int i = 0;
		input_buffer = sspi_FindSecBuffer(pInput, SECBUFFER_TOKEN);

		if (!input_buffer)
			return SEC_E_INVALID_TOKEN;

		if (input_buffer->cbBuffer < 1)
			return SEC_E_INVALID_TOKEN;

		input_tok.value = input_buffer->pvBuffer;
		input_tok.length = input_buffer->cbBuffer;

		context->major_status = gss_init_sec_context(&(context->minor_status),
							     context->cred,
							     &(context->gss_ctx),
							     context->target_name,
							     desired_mech,
							     GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG,
							     GSS_C_INDEFINITE,
							     GSS_C_NO_CHANNEL_BINDINGS,
							     &input_tok,
							     &actual_mech,
							     &output_tok, &actual_services,
							     &(context->actual_time));
		if (GSS_ERROR(context->major_status))
		{
			if (i == 0)
				WLog_ERR(TAG, "Kerberos: Initialize failed, do you have correct kerberos tgt initialized ?\n");
			else
				WLog_ERR(TAG, "Kerberos: Negotiation failed.\n");

			WLog_ERR(TAG, "Kerberos: gss_init_sec_context failed with %lu\n", GSS_C_GSS_CODE);
			/*
			cssp_gss_report_error(GSS_C_GSS_CODE, "Kerberos: SPNEGO negotiation failed.",
					      context->major_status, context->minor_status);
			*/

			return -1;
		}
#ifdef WITH_DEBUG_NEGO
		printf("######## output_tok.length = %lu\n", output_tok.length);
#endif
		if (output_tok.length == 0)
		{
			/* Frees output_buffer to detect second call in NLA */
			output_buffer = sspi_FindSecBuffer(pOutput, SECBUFFER_TOKEN);
#ifdef WITH_DEBUG_NEGO
			printf("Second GSS Call, output_buffer is %p, input_buffer is %d\n",
			       output_buffer, input_buffer->cbBuffer);
#endif
			sspi_SecBufferFree(output_buffer);
			return SEC_E_OK;
		}
		else
		{
			/* FIXME */
			printf("3rd GSSAPI call, untested should not end up here");
			return SEC_E_INTERNAL_ERROR;
		}
	}

	return SEC_E_INTERNAL_ERROR;
}

SECURITY_STATUS SEC_ENTRY
kerberos_QueryContextAttributesW(PCtxtHandle phContext, ULONG ulAttribute, void *pBuffer)
{
	return SEC_E_OK;
}

SECURITY_STATUS SEC_ENTRY
kerberos_QueryContextAttributesA(PCtxtHandle phContext, ULONG ulAttribute, void *pBuffer)
{

#ifdef WITH_DEBUG_NEGO
	printf("debug: kerberos_QueryContextAttributesA\n");
#endif

	if (!phContext)
		return SEC_E_INVALID_HANDLE;

	if (!pBuffer)
		return SEC_E_INSUFFICIENT_MEMORY;

	if (ulAttribute == SECPKG_ATTR_SIZES)
	{
		SecPkgContext_Sizes *ContextSizes = (SecPkgContext_Sizes *) pBuffer;

		/* FIXME: Hard-coded size is ugly */
		ContextSizes->cbMaxToken = 2010;
		ContextSizes->cbMaxSignature = 0;
		ContextSizes->cbBlockSize = 60;
		ContextSizes->cbSecurityTrailer = 0;

		return SEC_E_OK;
	}

	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY
kerberos_EncryptMessage(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage,
			ULONG MessageSeqNo)
{
	int index;
	KRB_CONTEXT *context;
	PSecBuffer data_buffer = NULL;
	PSecBuffer signature_buffer = NULL;
	context = (KRB_CONTEXT *) sspi_SecureHandleGetLowerPointer(phContext);

#ifdef WITH_DEBUG_NEGO
	printf("kerberos_EncryptMessage\n");
#endif
	for (index = 0; index < (int) pMessage->cBuffers; index++)
	{
		if (pMessage->pBuffers[index].BufferType == SECBUFFER_DATA)
			data_buffer = &pMessage->pBuffers[index];
		else if (pMessage->pBuffers[index].BufferType == SECBUFFER_TOKEN)
			signature_buffer = &pMessage->pBuffers[index];
	}

	if (!data_buffer)
		return SEC_E_INVALID_TOKEN;

	if (!signature_buffer)
		return SEC_E_INVALID_TOKEN;

#ifdef WITH_DEBUG_NEGO
	printf("Input data:\n");
	for (index = 0; index < data_buffer->cbBuffer; index++)
	{
		printf("%02x", ((unsigned char *) data_buffer->pvBuffer)[index]);
	}
	printf("\n");
#endif
	if (!call_gss_wrap(context->gss_ctx, data_buffer, signature_buffer))
	{
		printf("Something went wrong with call_gss_wrap!\n");
		return SEC_E_INTERNAL_ERROR;
	}
#ifdef WITH_DEBUG_NEGO
	printf("GSS_WRAPPED data (len: %d):\n", signature_buffer->cbBuffer);
	for (index = 0; index < signature_buffer->cbBuffer; index++)
	{
		printf("%02x", ((unsigned char *) signature_buffer->pvBuffer)[index]);
	}
	printf("\n");
#endif

	return SEC_E_OK;
}

SECURITY_STATUS SEC_ENTRY
kerberos_DecryptMessage(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo,
			ULONG * pfQOP)
{
	int index;
	KRB_CONTEXT *context;
	PSecBuffer data_buffer = NULL;
	PSecBuffer signature_buffer = NULL;
	context = (KRB_CONTEXT *) sspi_SecureHandleGetLowerPointer(phContext);

#ifdef WITH_DEBUG_NEGO
	printf("kerberos_DecryptMessage\n");
#endif
	for (index = 0; index < (int) pMessage->cBuffers; index++)
	{
		if (pMessage->pBuffers[index].BufferType == SECBUFFER_DATA)
			data_buffer = &pMessage->pBuffers[index];
		else if (pMessage->pBuffers[index].BufferType == SECBUFFER_TOKEN)
			signature_buffer = &pMessage->pBuffers[index];
	}

	if (!data_buffer)
		return SEC_E_INVALID_TOKEN;

	if (!signature_buffer)
		return SEC_E_INVALID_TOKEN;

#ifdef WITH_DEBUG_NEGO
	printf("Input data:\n");
	for (index = 0; index < data_buffer->cbBuffer; index++)
	{
		printf("%02x", ((unsigned char *) data_buffer->pvBuffer)[index]);
	}
	printf("\n");
#endif
	if (!call_gss_unwrap(context->gss_ctx, data_buffer, signature_buffer))
	{
		printf("Something went wrong with call_gss_unwrap!\n");
		return SEC_E_INTERNAL_ERROR;
	}
#ifdef WITH_DEBUG_NEGO
	printf("GSS_UNWRAPPED data:\n");
	for (index = 0; index < signature_buffer->cbBuffer; index++)
	{
		printf("%02x", ((unsigned char *) signature_buffer->pvBuffer)[index]);
	}
	printf("\n");
#endif

	return SEC_E_OK;
}

SECURITY_STATUS SEC_ENTRY
kerberos_MakeSignature(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage,
		       ULONG MessageSeqNo)
{
#ifdef WITH_DEBUG_NEGO
	printf("kerberos_MakeSignature\n");
#endif
	return SEC_E_OK;
}

SECURITY_STATUS SEC_ENTRY
kerberos_VerifySignature(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo,
			 ULONG * pfQOP)
{
#ifdef WITH_DEBUG_NEGO
	printf("kerberos_VerifySignature\n");
#endif
	return SEC_E_OK;
}

const SecPkgInfoA KERBEROS_SecPkgInfoA = {
	0x000F3BBF,		/* fCapabilities */
	1,			/* wVersion */
	0x0010,			/* wRPCID */
	0x00002EE0,		/* cbMaxToken */
	"Kerberos",		/* Name */
	"Microsoft Kerberos V1.0"	/* Comment */
};

WCHAR KERBEROS_SecPkgInfoW_Name[] = { 'K', 'e', 'r', 'b', 'e', 'r', 'o', 's', '\0' };

WCHAR KERBEROS_SecPkgInfoW_Comment[] = {
	'K', 'e', 'r', 'b', 'e', 'r', 'o', 's', ' ',
	'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', ' ',
	'P', 'a', 'c', 'k', 'a', 'g', 'e', '\0'
};

const SecPkgInfoW KERBEROS_SecPkgInfoW = {
	0x000F3BBF,		/* fCapabilities */
	1,			/* wVersion */
	0x0010,			/* wRPCID */
	0x00002EE0,		/* cbMaxToken */
	KERBEROS_SecPkgInfoW_Name,	/* Name */
	KERBEROS_SecPkgInfoW_Comment	/* Comment */
};

const SecurityFunctionTableA KERBEROS_SecurityFunctionTableA = {
	1,			/* dwVersion */
	NULL,			/* EnumerateSecurityPackages */
	kerberos_QueryCredentialsAttributesA,	/* QueryCredentialsAttributes */
	kerberos_AcquireCredentialsHandleA,	/* AcquireCredentialsHandle */
	kerberos_FreeCredentialsHandle,	/* FreeCredentialsHandle */
	NULL,			/* Reserved2 */
	kerberos_InitializeSecurityContextA,	/* InitializeSecurityContext */
	NULL,			/* AcceptSecurityContext */
	NULL,			/* CompleteAuthToken */
	NULL,			/* DeleteSecurityContext */
	NULL,			/* ApplyControlToken */
	kerberos_QueryContextAttributesA,	/* QueryContextAttributes */
	NULL,			/* ImpersonateSecurityContext */
	NULL,			/* RevertSecurityContext */
	kerberos_MakeSignature,	/* MakeSignature */
	kerberos_VerifySignature,	/* VerifySignature */
	NULL,			/* FreeContextBuffer */
	NULL,			/* QuerySecurityPackageInfo */
	NULL,			/* Reserved3 */
	NULL,			/* Reserved4 */
	NULL,			/* ExportSecurityContext */
	NULL,			/* ImportSecurityContext */
	NULL,			/* AddCredentials */
	NULL,			/* Reserved8 */
	NULL,			/* QuerySecurityContextToken */
	kerberos_EncryptMessage,	/* EncryptMessage */
	kerberos_DecryptMessage,	/* DecryptMessage */
	NULL,			/* SetContextAttributes */
};

const SecurityFunctionTableW KERBEROS_SecurityFunctionTableW = {
	1,			/* dwVersion */
	NULL,			/* EnumerateSecurityPackages */
	kerberos_QueryCredentialsAttributesW,	/* QueryCredentialsAttributes */
	kerberos_AcquireCredentialsHandleW,	/* AcquireCredentialsHandle */
	kerberos_FreeCredentialsHandle,	/* FreeCredentialsHandle */
	NULL,			/* Reserved2 */
	kerberos_InitializeSecurityContextW,	/* InitializeSecurityContext */
	NULL,			/* AcceptSecurityContext */
	NULL,			/* CompleteAuthToken */
	NULL,			/* DeleteSecurityContext */
	NULL,			/* ApplyControlToken */
	kerberos_QueryContextAttributesW,	/* QueryContextAttributes */
	NULL,			/* ImpersonateSecurityContext */
	NULL,			/* RevertSecurityContext */
	kerberos_MakeSignature,	/* MakeSignature */
	kerberos_VerifySignature,	/* VerifySignature */
	NULL,			/* FreeContextBuffer */
	NULL,			/* QuerySecurityPackageInfo */
	NULL,			/* Reserved3 */
	NULL,			/* Reserved4 */
	NULL,			/* ExportSecurityContext */
	NULL,			/* ImportSecurityContext */
	NULL,			/* AddCredentials */
	NULL,			/* Reserved8 */
	NULL,			/* QuerySecurityContextToken */
	kerberos_EncryptMessage,	/* EncryptMessage */
	kerberos_DecryptMessage,	/* DecryptMessage */
	NULL,			/* SetContextAttributes */
};
