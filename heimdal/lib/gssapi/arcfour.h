/*
 * Copyright (c) 2003 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

/* $Id: arcfour.h,v 1.5 2004/03/07 22:30:57 lha Exp $ */

#ifndef GSSAPI_ARCFOUR_H_
#define GSSAPI_ARCFOUR_H_ 1

#define GSS_ARCFOUR_WRAP_TOKEN_SIZE 32

OM_uint32 _gssapi_wrap_arcfour(OM_uint32 *minor_status,
			       const gss_ctx_id_t context_handle,
			       int conf_req_flag,
			       gss_qop_t qop_req,
			       const gss_buffer_t input_message_buffer,
			       int *conf_state,
			       gss_buffer_t output_message_buffer,
			       krb5_keyblock *key);

OM_uint32 _gssapi_unwrap_arcfour(OM_uint32 *minor_status,
				 const gss_ctx_id_t context_handle,
				 const gss_buffer_t input_message_buffer,
				 gss_buffer_t output_message_buffer,
				 int *conf_state,
				 gss_qop_t *qop_state,
				 krb5_keyblock *key);

OM_uint32 _gssapi_get_mic_arcfour(OM_uint32 *minor_status,
				  const gss_ctx_id_t context_handle,
				  gss_qop_t qop_req,
				  const gss_buffer_t message_buffer,
				  gss_buffer_t message_token,
				  krb5_keyblock *key);

OM_uint32 _gssapi_verify_mic_arcfour(OM_uint32 *minor_status,
				     const gss_ctx_id_t context_handle,
				     const gss_buffer_t message_buffer,
				     const gss_buffer_t token_buffer,
				     gss_qop_t *qop_state,
				     krb5_keyblock *key,
				     char *type);

#endif /* GSSAPI_ARCFOUR_H_ */
