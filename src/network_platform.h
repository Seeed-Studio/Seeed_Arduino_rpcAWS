/*
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Additions Copyright 2016 Espressif Systems (Shanghai) PTE LTD
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifndef IOTSDKC_NETWORK_MBEDTLS_PLATFORM_H_H

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief TLS Connection Parameters
 *
 * Defines a type containing TLS specific parameters to be passed down to the
 * TLS networking layer to create a TLS secured socket.
 */
typedef struct _TLSDataParams {
    int socket;
    uint32_t flags;
    void *ssl_client;
    bool connected;
    uint32_t conn_staus;
}TLSDataParams;

#define IOTSDKC_NETWORK_MBEDTLS_PLATFORM_H_H

#ifdef __cplusplus
}
#endif

#endif //IOTSDKC_NETWORK_MBEDTLS_PLATFORM_H_H
