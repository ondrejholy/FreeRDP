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

#ifndef FREERDP_SSPI_KERBEROS_GSS_PRIVATE_H
#define FREERDP_SSPI_KERBEROS_GSS_PRIVATE_H

int convert_spn_to_gss_service_name(char *server, gss_name_t * name);

int call_gss_wrap(gss_ctx_id_t ctx, PSecBuffer in, PSecBuffer out);

int call_gss_unwrap(gss_ctx_id_t ctx, PSecBuffer in, PSecBuffer out);

#endif /* FREERDP_SSPI_KERBEROS_GSS_PRIVATE_H */
