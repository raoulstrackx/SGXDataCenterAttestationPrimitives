/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/**
 * File: utility.cpp
 *
 * Description: utility functions
 *
 */
#include <stdio.h>
#include <string>
#ifdef _MSC_VER
#include <Windows.h>
#include <tchar.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif
#include "id_enclave_u.h"
#include "pce_u.h"
#include "sgx_urts.h"     
#include "utility.h"
#include <openssl/rsa.h>     // For RSA functions
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif
// Use secure HTTPS certificate or not
extern bool g_use_secure_cert ;


#ifdef DEBUG
#define PRINT_MESSAGE(message) printf(message);
#define PRINT_MESSAGE2(message1,message2) printf(message1, message2);
#else
#define PRINT_MESSAGE(message) ;
#define PRINT_MESSAGE2(message1,message2) ;
#endif

#ifdef  _MSC_VER                
#define PCE_ENCLAVE_NAME  _T("pce.signed.dll")
#define ID_ENCLAVE_NAME   _T("id_enclave.signed.dll")
#define SGX_URTS_LIBRARY _T("sgx_urts.dll")
#define SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY _T("mp_uefi.dll")
#define FINDFUNCTIONSYM   GetProcAddress
#define CLOSELIBRARYHANDLE  FreeLibrary
#define EFIVARS_FILE_SYSTEM_IN_OS ""//for Windows OS, don't need this path

HINSTANCE sgx_urts_handle = NULL;
#ifdef UNICODE
typedef sgx_status_t (SGXAPI *sgx_create_enclave_func_t)(const LPCWSTR file_name, const int debug, sgx_launch_token_t* launch_token, int* launch_token_updated, sgx_enclave_id_t* enclave_id, sgx_misc_attribute_t* misc_attr);
#else 
typedef sgx_status_t (SGXAPI *sgx_create_enclave_func_t)(const LPCSTR file_name, const int debug, sgx_launch_token_t* launch_token, int* launch_token_updated, sgx_enclave_id_t* enclave_id, sgx_misc_attribute_t* misc_attr);
#endif

#else
#define PCE_ENCLAVE_NAME  "libsgx_pce.signed.so.1"
#define ID_ENCLAVE_NAME   "libsgx_id_enclave.signed.so.1"
#define SGX_URTS_LIBRARY "libsgx_urts.so"             
#define SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY "libmpa_uefi.so.1"
#define FINDFUNCTIONSYM   dlsym
#define CLOSELIBRARYHANDLE  dlclose
#define EFIVARS_FILE_SYSTEM_IN_OS "/sys/firmware/efi/efivars/"
typedef sgx_status_t (SGXAPI *sgx_create_enclave_func_t)(const char* file_name,
    const int debug,
    sgx_launch_token_t* launch_token,
    int* launch_token_updated,
    sgx_enclave_id_t* enclave_id,
    sgx_misc_attribute_t* misc_attr);


void* sgx_urts_handle = NULL;
#endif 


typedef sgx_status_t(SGXAPI* sgx_ecall_func_t)(const sgx_enclave_id_t eid,
    const int index,
    const void* ocall_table,
    void* ms);

typedef sgx_status_t (SGXAPI* sgx_destroy_enclave_func_t)(const sgx_enclave_id_t enclave_id);
typedef sgx_status_t (SGXAPI* sgx_get_target_info_func_t)(const sgx_enclave_id_t enclave_id, sgx_target_info_t* target_info);

#ifdef _MSC_VER
#pragma warning(disable: 4201)    // used to eliminate `unused variable' warning
#define UNUSED(val) (void)(val)

#endif 
#include "MPUefi.h"
typedef MpResult(*mp_uefi_init_func_t)(const char* path, const LogLevel logLevel);
typedef MpResult(*mp_uefi_get_request_type_func_t)(MpRequestType* type);
typedef MpResult(*mp_uefi_get_request_func_t)(uint8_t *request, uint16_t *request_size);
typedef MpResult(*mp_uefi_get_registration_status_func_t)(MpRegistrationStatus* status);
typedef MpResult(*mp_uefi_set_registration_status_func_t)(const MpRegistrationStatus* status);
typedef MpResult(*mp_uefi_terminate_func_t)();



//redefine this function to avoid sgx_urts library compile dependency
sgx_status_t  SGXAPI sgx_ecall(const sgx_enclave_id_t eid,
                              const int index,
                              const void* ocall_table,
                              void* ms)
{
    // sgx_urts library has been tried to loaded before this function call, and this function is be called during sgx_create_enclave call
#if defined(_MSC_VER)
    if (sgx_urts_handle == NULL) {
        printf("ERROR: didn't find the sgx_urts.dll library, please make sure you have installed PSW installer package. \n");
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_ecall_func_t p_sgx_ecall = (sgx_ecall_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_ecall");
    if(p_sgx_ecall != NULL) {
        return p_sgx_ecall(eid, index, ocall_table, ms);
    }
    else {
        printf("ERROR: didn't find function sgx_ecall in the sgx_urts.dll library. \n");
        return SGX_ERROR_UNEXPECTED;
    }
#else
    if (sgx_urts_handle == NULL) {
        printf("ERROR: didn't find the sgx_urts.so library, please make sure you have installed sgx_urts installer package. \n");
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_ecall_func_t p_sgx_ecall = (sgx_ecall_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_ecall");
    if(p_sgx_ecall != NULL ) {
        return p_sgx_ecall(eid, index, ocall_table, ms);
    }
    else {
        printf("ERROR: didn't find function sgx_ecall in the sgx_urts.dll library. \n");
        return SGX_ERROR_UNEXPECTED;
    }
#endif

}


#ifdef _MSC_VER
bool get_program_path(TCHAR *p_file_path, size_t buf_size)
{
    UNUSED(p_file_path);
    UNUSED(buf_size);
    return true;
}
#else
bool get_program_path(char *p_file_path, size_t buf_size)
{
    if(NULL == p_file_path || 0 == buf_size){
        return false;
    }

    ssize_t i = readlink( "/proc/self/exe", p_file_path, buf_size );
    if (i == -1)
        return false;
    p_file_path[i] = '\0';

    char* p_last_slash = strrchr(p_file_path, '/' );
    if ( p_last_slash != NULL ) {
        p_last_slash++;   //increment beyond the last slash
        *p_last_slash = '\0';  //null terminate the string
    }
    else {
        p_file_path[0] = '\0';
    }
    return true;
}
#endif


bool get_urts_library_handle()
{
    // try to sgx_urts library to create enclave.
#if defined(_MSC_VER)
    sgx_urts_handle = LoadLibrary(SGX_URTS_LIBRARY);
    if (sgx_urts_handle == NULL) {
        printf("ERROR: didn't find the sgx_urts.dll library, please make sure you have installed PSW installer package. \n");
        return false;
    }
#else
    sgx_urts_handle = dlopen(SGX_URTS_LIBRARY, RTLD_LAZY);
    if (sgx_urts_handle == NULL) {
        printf("ERROR: didn't find the sgx_urts.so library, please make sure you have installed sgx_urts installer package. \n");
        return false;
    }
#endif
    return true;
}

void close_urts_library_handle()
{
    CLOSELIBRARYHANDLE(sgx_urts_handle);
}

extern "C"
#if defined(_MSC_VER)
bool load_enclave(const TCHAR* enclave_name, sgx_enclave_id_t* p_eid)
#else
bool load_enclave(const char* enclave_name, sgx_enclave_id_t* p_eid)
#endif
{
    bool ret = true;
    sgx_status_t sgx_status = SGX_SUCCESS;
    int launch_token_updated = 0;
    sgx_launch_token_t launch_token = { 0 };
    memset(&launch_token, 0, sizeof(sgx_launch_token_t));

#if defined(_MSC_VER)
    TCHAR enclave_path[MAX_PATH] = _T("");
#else
    char enclave_path[MAX_PATH] = "";
#endif

    if (!get_program_path(enclave_path, MAX_PATH - 1))
        return false;
#if defined(_MSC_VER)    
    if (_tcsnlen(enclave_path, MAX_PATH) + _tcsnlen(enclave_name, MAX_PATH) + sizeof(char) > MAX_PATH)
        return false;
    (void)_tcscat_s(enclave_path, MAX_PATH, enclave_name);

#ifdef UNICODE
    sgx_create_enclave_func_t p_sgx_create_enclave = (sgx_create_enclave_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_create_enclavew");
#else
    sgx_create_enclave_func_t p_sgx_create_enclave = (sgx_create_enclave_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_create_enclavea");
#endif
#else
    if (strnlen(enclave_path, MAX_PATH) + strnlen(enclave_name, MAX_PATH) + sizeof(char) > MAX_PATH)
        return false;
    (void)strncat(enclave_path, enclave_name, strnlen(enclave_name, MAX_PATH));

    sgx_create_enclave_func_t p_sgx_create_enclave = (sgx_create_enclave_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_create_enclave");
#endif


    if (p_sgx_create_enclave == NULL ) {
        printf("ERROR: Can't find the function sgx_create_enclave in sgx_urts library.\n");
        return false;
    }
    
    sgx_status = p_sgx_create_enclave(enclave_path,
        0,
        &launch_token,
        &launch_token_updated,
        p_eid,
        NULL);
    if (SGX_SUCCESS != sgx_status) {
        printf("Error, call sgx_create_enclave: fail [%s], SGXError:%04x.\n",__FUNCTION__, sgx_status);
        ret = false;
    }

    return ret;
}

void unload_enclave(sgx_enclave_id_t* p_eid)
{
    sgx_destroy_enclave_func_t p_sgx_destroy_enclave = (sgx_destroy_enclave_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_destroy_enclave");
    if (p_sgx_destroy_enclave == NULL) {
        printf("ERROR: Can't find the function sgx_destory_enclave in sgx_urts library.\n");
        return;
    }
    p_sgx_destroy_enclave(*p_eid);
}


// for multi-package platform, get the platform manifet
// return value:
//  UEFI_OPERATION_SUCCESS: successfully get the platform manifest.
//  UEFI_OPERATION_VARIABLE_NOT_AVAILABLE: it means platform manifest is not avaible: it is not multi-package platform or platform manifest has been consumed.
//  UEFI_OPERATION_LIB_NOT_AVAILABLE: it means that the uefi shared library doesn't exist
//  UEFI_OPERATION_FAIL:  it is one add package request, now we don't support it. 
//  UEFI_OPERATION_UNEXPECTED_ERROR: error happens.
uefi_status_t get_platform_manifest(uint8_t ** buffer, uint16_t &out_buffer_size)
{
    uefi_status_t ret = UEFI_OPERATION_UNEXPECTED_ERROR;
#ifdef _MSC_VER
    HINSTANCE uefi_lib_handle = LoadLibrary(SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY);
    if (uefi_lib_handle != NULL) {
        PRINT_MESSAGE("Found the UEFI library. \n");
    }
    else {
        out_buffer_size = 0;
        buffer = NULL;
        printf("Warning: If this is a multi-package platform, please install registration agent package.\n");
        printf("         otherwise, the platform manifest information will NOT be retrieved.\n");
        return UEFI_OPERATION_LIB_NOT_AVAILABLE;
    }
#else
    void *uefi_lib_handle = dlopen(SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY, RTLD_LAZY);
    if (uefi_lib_handle != NULL) {
        PRINT_MESSAGE("Found the UEFI library. \n");
    }
    else {
        out_buffer_size = 0;
        buffer = NULL;
        printf("Warning: If this is a multi-package platform, please install registration agent package.\n");
        printf("         otherwise, the platform manifest information will NOT be retrieved.\n");
        return UEFI_OPERATION_LIB_NOT_AVAILABLE;
    }
#endif
    mp_uefi_init_func_t p_mp_uefi_init = (mp_uefi_init_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_init");
    mp_uefi_get_request_type_func_t p_mp_uefi_get_request_type = (mp_uefi_get_request_type_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_get_request_type");
    mp_uefi_get_request_func_t p_mp_uefi_get_request = (mp_uefi_get_request_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_get_request");
    mp_uefi_get_registration_status_func_t p_mp_uefi_get_registration_status = (mp_uefi_get_registration_status_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_get_registration_status");
    mp_uefi_terminate_func_t p_mp_uefi_terminate = (mp_uefi_terminate_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_terminate");
    if (p_mp_uefi_init == NULL ||
        p_mp_uefi_get_request_type == NULL ||
        p_mp_uefi_get_request == NULL ||
        p_mp_uefi_get_registration_status == NULL ||
        p_mp_uefi_terminate == NULL) {
        printf("Error: couldn't find uefi function interface(s) in the UEFI shared library.\n");
        CLOSELIBRARYHANDLE(uefi_lib_handle);
        return ret;
    }

    MpResult mpResult = MP_SUCCESS;
    MpRequestType type = MP_REQ_NONE;
    mpResult = p_mp_uefi_init(EFIVARS_FILE_SYSTEM_IN_OS, MP_REG_LOG_LEVEL_NONE);
    if (mpResult != MP_SUCCESS) {
        printf("Error: couldn't init UEFI shared library.\n");
        CLOSELIBRARYHANDLE(uefi_lib_handle);
        return ret;
    }
    do {
        mpResult = p_mp_uefi_get_request_type(&type);
        if (mpResult == MP_SUCCESS) {
            if (type == MP_REQ_REGISTRATION) {
                *buffer = new (std::nothrow) unsigned char[UINT16_MAX];
                mpResult = p_mp_uefi_get_request(*buffer, &out_buffer_size);
                if (mpResult != MP_SUCCESS) {
                    printf("Error: Couldn't get the platform manifest information.\n");
                    break;
                }
            }
            else if (type == MP_REQ_ADD_PACKAGE) {
                printf("Error: Add Package type is not supported.\n");
                ret = UEFI_OPERATION_FAIL;
                break;
            }
            else {
                printf("Warning: platform manifest is not available or current platform is not multi-package platform.\n");
                ret = UEFI_OPERATION_VARIABLE_NOT_AVAILABLE;
                break;
            }
        }
        else {
            MpRegistrationStatus status;
            MpResult mpResult_registration_status = p_mp_uefi_get_registration_status(&status);
            if (mpResult_registration_status != MP_SUCCESS) {
                printf("Warning: error occurred while getting registration status, the error code is: %d \n", mpResult_registration_status);
                break;
            }
            if(status.registrationStatus == MP_TASK_COMPLETED){
                printf("Warning: registration has completed, so platform manifest has been removed. \n");
                ret = UEFI_OPERATION_VARIABLE_NOT_AVAILABLE;
                break;
            }
            else {
                printf("Error: get UEFI request type error, and the error code is: %d.\n", mpResult);
                break;
            }
        }
        ret = UEFI_OPERATION_SUCCESS;
    } while (0);
    p_mp_uefi_terminate();

    if (uefi_lib_handle != NULL) {
        CLOSELIBRARYHANDLE(uefi_lib_handle);
    }
    return ret;
}


// for multi-package platform, set registration status 
// return value:
//  UEFI_OPERATION_SUCCESS: successfully set the platform's registration status.
//  UEFI_OPERATION_LIB_NOT_AVAILABLE: it means that the uefi shared library doesn't exist, maybe the registration agent package is not installed
//  UEFI_OPERATION_UNEXPECTED_ERROR: error happens.
uefi_status_t set_registration_status()
{
    uefi_status_t ret = UEFI_OPERATION_UNEXPECTED_ERROR;
#ifdef _MSC_VER
    HINSTANCE uefi_lib_handle = LoadLibrary(SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY);
    if (uefi_lib_handle != NULL) {
        PRINT_MESSAGE("Found the UEFI library. \n");
    }
    else {
        printf("Warning: If this is a multi-package platform, please install registration agent package.\n");
        printf("         otherwise, the platform manifest information will NOT be retrieved.\n");
        return UEFI_OPERATION_LIB_NOT_AVAILABLE;
    }
#else
    void *uefi_lib_handle = dlopen(SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY, RTLD_LAZY);
    if (uefi_lib_handle != NULL) {
        PRINT_MESSAGE("Found the UEFI library. \n");
    }
    else {
        printf("Warning: If this is a multi-package platform, please install registration agent package.\n");
        printf("         otherwise, the platform manifest information will NOT be retrieved.\n");
        return UEFI_OPERATION_LIB_NOT_AVAILABLE;
    }
#endif
    mp_uefi_init_func_t p_mp_uefi_init = (mp_uefi_init_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_init");
    mp_uefi_set_registration_status_func_t p_mp_uefi_set_registration_status = (mp_uefi_set_registration_status_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_set_registration_status");
    mp_uefi_terminate_func_t p_mp_uefi_terminate = (mp_uefi_terminate_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_terminate");
    if (p_mp_uefi_init == NULL ||
        p_mp_uefi_set_registration_status == NULL ||
        p_mp_uefi_terminate == NULL) {
        printf("Error: couldn't find uefi function interface(s) in the multi-package agent shared library.\n");
        CLOSELIBRARYHANDLE(uefi_lib_handle);
        return ret;
    }

    MpResult mpResult = MP_SUCCESS;
    MpRegistrationStatus status;
    mpResult = p_mp_uefi_init(EFIVARS_FILE_SYSTEM_IN_OS, MP_REG_LOG_LEVEL_NONE);
    if (mpResult != MP_SUCCESS) {
        printf("Error: couldn't init uefi shared library.\n");
        CLOSELIBRARYHANDLE(uefi_lib_handle);
        return ret;
    }

    status.registrationStatus = MP_TASK_COMPLETED;
    status.errorCode = MPA_SUCCESS;
    mpResult = p_mp_uefi_set_registration_status(&status);
    if (mpResult == MP_INSUFFICIENT_PRIVILEGES) {
        printf("Warning: the UEFI variable was in read-only mode, could NOT write it. \n");
    }
    else if (mpResult != MP_SUCCESS) {
        printf("Warning: error occurred while setting registration status, the error code is: %d \n", mpResult);
    }
    else {
        ret = UEFI_OPERATION_SUCCESS;
    }
    
    p_mp_uefi_terminate();

    if (uefi_lib_handle != NULL) {
        CLOSELIBRARYHANDLE(uefi_lib_handle);
    }
    return ret;
}

RSA* load_public_key_from_memory(const char* key_pem) {
    BIO* bio = BIO_new_mem_buf(key_pem, -1);
    if (!bio) {
        fprintf(stderr, "Error creating BIO buffer.");
        return nullptr;
    }
    RSA* rsa_public_key = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!rsa_public_key) {
        fprintf(stderr, "Error loading public key from memory.");
        return nullptr;
    }
    return rsa_public_key;
}

RSA* load_private_key_from_memory(const char* key_pem) {
    BIO* bio = BIO_new_mem_buf(key_pem, -1);
    if (!bio) {
        fprintf(stderr, "Error creating BIO buffer.");
        return nullptr;
    }

    RSA* rsa_private_key = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsa_private_key) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error loading private key from memory.");
        return nullptr;
    }

    return rsa_private_key;
}

bool populate_public_key(RSA* rsa_public_key, uint8_t* enc_public_key) {
    const BIGNUM* n = RSA_get0_n(rsa_public_key);
    const BIGNUM* e = RSA_get0_e(rsa_public_key);

    // Convert modulus to bytes
    int n_bytes = BN_bn2bin(n, enc_public_key);
    if (n_bytes < 0 || n_bytes > REF_RSA_OAEP_3072_MOD_SIZE) {
        fprintf(stderr, "Error converting modulus to bytes.");
        return false;
    }

    // Convert exponent to bytes
    int e_bytes = BN_bn2bin(e, enc_public_key + REF_RSA_OAEP_3072_MOD_SIZE);
    if (e_bytes < 0 || e_bytes > REF_RSA_OAEP_3072_EXP_SIZE) {
        fprintf(stderr,"Error converting exponent to bytes.");
        return false;
    }

    return true;
}

// Utility function to handle key loading and population
bool load_and_populate_key(const char* public_key_pem, uint8_t* enc_public_key) {
    RSA* rsa_public_key = load_public_key_from_memory(public_key_pem);
    if (!rsa_public_key) {
        return false;
    }

    bool result = populate_public_key(rsa_public_key, enc_public_key);
    RSA_free(rsa_public_key);
    return result;
}

void print_decrypted_ppid(unsigned char decrypted_ppid[], size_t length) {
    printf("Decrypted PPID: ");
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", decrypted_ppid[i]); // Print each byte in hex
    }
    printf("\n");
}

RSA* generate_identity_rsa_key() {
    RSA* rsa = RSA_new();
    BIGNUM* n = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* d = BN_new();

 
    BN_set_word(n, 17);
    
    // Set both public and private exponents to 1
    BN_set_word(e, 1);
    BN_set_word(d, 1);

    // Set RSA key components
    RSA_set0_key(rsa, n, e, d);

    return rsa;
}

int collect_data(uint8_t **pp_data_buffer)
{
    const char* private_key_pem = R"(-----BEGIN PRIVATE KEY-----
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
nvld+W+urv1bTEzbASAq5lwE
-----END PRIVATE KEY-----
    )";

 const char* public_key_pem = R"(-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAts/jU3KtghO8rKdwPGrd
BW4S0YgcrcrWLRF4+pARxyQFGR5+M77Woxb1xzhfACA4wNhpV7maa8nRmNACahP5
akNXRwevkfC+VN0Be6hVzHa0FvmTrCoi94cR1Y5ZfY0RRa5MY3Hu7w5iHfnMb3U5
nBNCE48KpvSa/cMscp4BVVUnvqb36pSBYKzCrVqy3TdthYmZrcCgHaADP8+PhnKD
ykR6dwCmqMpeO/aB4CN70jT6xgZpjMiq1iXxgSdLRCzI4I+F3Nj6iopQTCWVCv25
dzW+l9NicxMrGxBS6CG1XMUpROHKW48PmQV7YpV+eKRID/OFd50O3Mc/il3qs/Mc
bkjwT340oziThk3j75dbteggBRkYY/gd27FylQpwtyDq2bkfvgOt4kGJSQ781j2l
U03cgjz2myRiaEYogNRQV9lLtCnb+OdUpR9Nfv6mhWp8pfamDumyHCT3RWcSS7ZT
fRBjJ5Y1FQO45rG37P/Fua9LwFV1pxt9eFdrIXd8Y9ZjAgMBAAE=
-----END PUBLIC KEY-----
    )";

    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_status_t ecall_ret = SGX_SUCCESS;
    sgx_key_128bit_t platform_id = { 0 };
    int ret = 0;
    uint32_t buffer_size = 0;
    uint8_t * p_temp = NULL;

    sgx_enclave_id_t pce_enclave_eid = 0;
    sgx_enclave_id_t id_enclave_eid = 0;
    
    sgx_report_t id_enclave_report;
    uint32_t enc_key_size = REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE;
    uint8_t enc_public_key[REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE];
    uint8_t encrypted_ppid[REF_RSA_OAEP_3072_MOD_SIZE];
uint8_t public_key_binary[REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE];
    uint32_t encrypted_ppid_ret_size;
    pce_info_t pce_info;
    uint8_t signature_scheme;
    sgx_target_info_t pce_target_info;

    sgx_get_target_info_func_t p_sgx_get_target_info = NULL;
unsigned char decrypted_ppid[ENCRYPTED_PPID_LENGTH];
    int decrypted_size = -1;
    bool load_flag = false;
RSA* identity_rsa_key = generate_identity_rsa_key();
    RSA* rsa_private_key = load_private_key_from_memory(private_key_pem);
    if (!rsa_private_key) {
        fprintf(stderr, "Failed to load RSA private key.\n");
        ret = -1;
        goto CLEANUP;
    }

    // populate public key array for `get_pc_info`
    if (!populate_public_key(identity_rsa_key, public_key_binary)) {
        fprintf(stderr, "Failed to load RSA public key.\n");
        ret = -1;
        goto CLEANUP;
    }

    load_flag = get_urts_library_handle();
    if(false == load_flag) {// can't find urts shared library to load enclave
        ret = -1;
        goto CLEANUP;
    }

    load_flag = load_enclave(ID_ENCLAVE_NAME, &id_enclave_eid);
    if(false == load_flag) { // can't load id_enclave.
        ret = -1;
        goto CLEANUP;
    }

    sgx_status = ide_get_id(id_enclave_eid, &ecall_ret, &platform_id);
    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "Failed to call into the ID_ENCLAVE:get_qe_id. 0x%04x.\n", sgx_status);
        ret = -1;
        goto CLEANUP;
    }

    if (SGX_SUCCESS != ecall_ret) {
        fprintf(stderr, "Failed to get QE_ID. 0x%04x.\n", ecall_ret);
        ret = -1;
        goto CLEANUP;
    }


    load_flag = load_enclave(PCE_ENCLAVE_NAME, &pce_enclave_eid);
    if(false == load_flag) { // can't load pce enclave.
        ret = -1;
        goto CLEANUP;
    }

    p_sgx_get_target_info = (sgx_get_target_info_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_get_target_info");
    if (p_sgx_get_target_info == NULL) {
        printf("ERROR: Can't find the function sgx_get_target_info in sgx_urts library.\n");
        ret = -1;
        goto CLEANUP;
    }

    sgx_status = p_sgx_get_target_info(pce_enclave_eid, &pce_target_info);
    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "Failed to get pce target info. The error code is:  0x%04x.\n", sgx_status);
        ret = -1;
        goto CLEANUP;
    }

    sgx_status = ide_get_pce_encrypt_key(id_enclave_eid,
                                         &ecall_ret,
                                         &pce_target_info,
                                         &id_enclave_report,
                                         PCE_ALG_RSA_OAEP_3072,
                                         PPID_RSA3072_ENCRYPTED,
                                         enc_key_size,
                                         public_key_binary);
    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "Failed to call into the ID_ENCLAVE: get_report_and_pce_encrypt_key. The error code is: 0x%04x.\n", sgx_status);
        ret = -1;
        goto CLEANUP;
    }

    if (SGX_SUCCESS != ecall_ret) {
        fprintf(stderr, "Failed to generate PCE encryption key. The error code is: 0x%04x.\n", ecall_ret);
        ret = -1;
        goto CLEANUP;
    }

    sgx_status = get_pc_info(pce_enclave_eid,
                              (uint32_t*) &ecall_ret,
                              &id_enclave_report,
                              public_key_binary,
                              enc_key_size,
                              PCE_ALG_RSA_OAEP_3072,
                              encrypted_ppid,
                              REF_RSA_OAEP_3072_MOD_SIZE,
                              &encrypted_ppid_ret_size,
                              &pce_info,
                              &signature_scheme);
    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "Failed to call into PCE enclave: get_pc_info. The error code is: 0x%04x.\n", sgx_status);
        ret = -1;
        goto CLEANUP;
    }
    if (SGX_SUCCESS != ecall_ret) {
        fprintf(stderr, "Failed to get PCE info. The error code is: 0x%04x.\n", ecall_ret);
        ret = -1;
        goto CLEANUP;
    }

    if (signature_scheme != PCE_NIST_P256_ECDSA_SHA256) {
        fprintf(stderr, "PCE returned incorrect signature scheme.\n");
        ret = -1;
        goto CLEANUP;
    }

    if (encrypted_ppid_ret_size != ENCRYPTED_PPID_LENGTH) {
        fprintf(stderr, "PCE returned incorrect encrypted PPID size.\n");
        ret = -1;
        goto CLEANUP;
    }

// Decrypt the data using the RSA private key

    decrypted_size = RSA_private_decrypt(REF_RSA_OAEP_3072_MOD_SIZE,
                                             encrypted_ppid,
                                             decrypted_ppid,
                                             rsa_private_key,
                                             RSA_PKCS1_OAEP_PADDING);

    if (decrypted_size == -1) {
//        fprintf(stderr, "Failed to decrypt using RSA private key.\n");
//        ret = -1;
//        goto CLEANUP;
    }

    print_decrypted_ppid(decrypted_ppid, ENCRYPTED_PPID_LENGTH);

    RSA_free(rsa_private_key);

    buffer_size = ENCRYPTED_PPID_LENGTH + CPU_SVN_LENGTH + ISV_SVN_LENGTH + PCE_ID_LENGTH + DEFAULT_PLATFORM_ID_LENGTH;
    *pp_data_buffer = (uint8_t *) malloc(buffer_size);

    if (NULL == *pp_data_buffer) {
        fprintf(stderr,"Couldn't allocate data buffer\n");
        ret = -1;
        goto CLEANUP;
    }
    memset(*pp_data_buffer, 0, buffer_size);
    p_temp = *pp_data_buffer;
    //encrypted ppid
    memcpy(p_temp, encrypted_ppid, ENCRYPTED_PPID_LENGTH);
    
    //pce id
    p_temp = p_temp + ENCRYPTED_PPID_LENGTH;
    memcpy(p_temp , &(pce_info.pce_id), PCE_ID_LENGTH);

    //cpu svn
    p_temp = p_temp + PCE_ID_LENGTH;
    memcpy(p_temp , id_enclave_report.body.cpu_svn.svn, CPU_SVN_LENGTH);
    
    //pce isv svn
    p_temp = p_temp + CPU_SVN_LENGTH;
    memcpy(p_temp , &(pce_info.pce_isvn), ISV_SVN_LENGTH);
    
    //platform id
    p_temp = p_temp + ISV_SVN_LENGTH;
    memcpy(p_temp , platform_id, DEFAULT_PLATFORM_ID_LENGTH);

    
CLEANUP:
    if(pce_enclave_eid != 0) {
        unload_enclave(&pce_enclave_eid);
    }
    if(id_enclave_eid != 0) {
        unload_enclave(&id_enclave_eid);
    }
    close_urts_library_handle();
    return ret;

}

bool is_valid_proxy_type(std::string& proxy_type) {
    if (proxy_type.compare("DEFAULT") == 0 ||
        proxy_type.compare("MANUAL")  == 0 ||
        proxy_type.compare("AUTO")    == 0 ||
        proxy_type.compare("DIRECT")  == 0 ) { 
        return true;
    }
    else {
        return false;
    }                
}

bool is_valid_use_secure_cert(std::string& use_secure_cert) {
    if (use_secure_cert.compare("TRUE") == 0 ) {
        return true;
    }
    else if(use_secure_cert.compare("FALSE") == 0) {
        g_use_secure_cert = false;
	return true;
    }
    else {
        return false;
    }  
}

bool is_valid_tcb_update_type(std::string& tcb_update_type) {
    if (tcb_update_type.compare("STANDARD") == 0 ||
        tcb_update_type.compare("EARLY")  == 0 ||
        tcb_update_type.compare("ALL")  == 0 ) { 
        return true;
    }
    else {
        return false;
    }                
}


/**
* Method converts byte containing value from 0x00-0x0F into its corresponding ASCII code,
* e.g. converts 0x00 to '0', 0x0A to 'A'.
* Note: This is mainly a helper method for internal use in byte_array_to_hex_string().
*
* @param in byte to be converted (allowed values: 0x00-0x0F)
*
* @return ASCII code representation of the byte or 0 if method failed (e.g input value was not in provided range).
*/
uint8_t convert_value_to_ascii(uint8_t in)
{
	if (in <= 0x09)
	{
		return (uint8_t)(in + '0');
	}
	else if (in <= 0x0F)
	{
		return (uint8_t)(in - 10 + 'A');
	}

	return 0;
}

//Function to do HEX encoding of array of bytes
//@param in_buf, bytes array whose length is in_size
//       out_buf, output the HEX encoding of in_buf on success.
//@return true on success and false on error
//The out_size must always be 2*in_size since each byte into encoded by 2 characters
bool byte_array_to_hex_string(const uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{
	if (in_size>UINT32_MAX / 2)return false;
	if (in_buf == NULL || out_buf == NULL || out_size != in_size * 2)return false;

	for (uint32_t i = 0; i< in_size; i++)
	{
		*out_buf++ = convert_value_to_ascii(static_cast<uint8_t>(*in_buf >> 4));
		*out_buf++ = convert_value_to_ascii(static_cast<uint8_t>(*in_buf & 0xf));
		in_buf++;
	}
	return true;
}
                     

/**
* This function appends request parameters of byte array type to the UR in HEX string format
*
* @param url Request UR
* @param request  Request parameter in byte array
* @param request_size Size of byte array
*
* @return true If the byte array was appended to the UR successfully
*/
network_post_error_t append_body_context(string& url, const uint8_t* request, const uint32_t request_size)
{
	if (request_size >= UINT32_MAX / 2)
		return POST_INVALID_PARAMETER_ERROR;

	uint8_t* hex = (uint8_t*)malloc(request_size * 2);
	if (!hex)
		return POST_OUT_OF_MEMORY_ERROR;
	if (!byte_array_to_hex_string(request, request_size, hex, request_size * 2)) {
		free(hex);
		return POST_UNEXPECTED_ERROR;
	}
	url.append(reinterpret_cast<const char*>(hex), request_size * 2);
	free(hex);
	return POST_SUCCESS;
}

network_post_error_t generate_json_message_body(const uint8_t *raw_data, 
                                                const uint32_t raw_data_size,
                                                const uint16_t platform_id_length,
                                                const bool non_enclave_mode, 
                                                string &jsonString)
{
    network_post_error_t ret = POST_SUCCESS;
    const uint8_t *position = raw_data;

    jsonString = "{";
    if (true == non_enclave_mode) {
        jsonString += "\"pce_id\": \"";
        if ((ret = append_body_context(jsonString, position, PCE_ID_LENGTH)) != POST_SUCCESS) {
            return ret;
        }
        jsonString += "\" ,\"qe_id\": \"";
        position = position + PCE_ID_LENGTH;
        if ((ret = append_body_context(jsonString, position, platform_id_length)) != POST_SUCCESS) {
            return ret;
        }

        jsonString += "\" ,\"platform_manifest\": \"";
        position = position + platform_id_length;
        if ((ret = append_body_context(jsonString, position, raw_data_size - PCE_ID_LENGTH - platform_id_length)) != POST_SUCCESS) {
            return ret;
        }
    }
    else {
        uint32_t left_size = raw_data_size - platform_id_length - CPU_SVN_LENGTH - ISV_SVN_LENGTH - PCE_ID_LENGTH - ENCRYPTED_PPID_LENGTH;
        jsonString += "\"enc_ppid\": \"";
        if ((ret = append_body_context(jsonString, position, ENCRYPTED_PPID_LENGTH)) != POST_SUCCESS) {
            return ret;
        }

        jsonString += "\" ,\"pce_id\": \"";
        position = position + ENCRYPTED_PPID_LENGTH;
        if ((ret = append_body_context(jsonString, position, PCE_ID_LENGTH)) != POST_SUCCESS) {
            return ret;
        }
        jsonString += "\" ,\"cpu_svn\": \"";
        position = position + PCE_ID_LENGTH;
        if ((ret = append_body_context(jsonString, position, CPU_SVN_LENGTH)) != POST_SUCCESS) {
            return ret;
        }

        jsonString += "\" ,\"pce_svn\": \"";
        position = position + CPU_SVN_LENGTH;
        if ((ret = append_body_context(jsonString, position, ISV_SVN_LENGTH)) != POST_SUCCESS) {
            return ret;
        }

        jsonString += "\" ,\"qe_id\": \"";
        position = position + ISV_SVN_LENGTH;
        if ((ret = append_body_context(jsonString, position, platform_id_length)) != POST_SUCCESS) {
            return ret;
        }

        jsonString += "\" ,\"platform_manifest\": \"";
        if (left_size != 0) {
            position = position + platform_id_length;
            if ((ret = append_body_context(jsonString, position, left_size)) != POST_SUCCESS) {
                return ret;
            }
        }

    }
    jsonString += "\" }";
    return ret;
}
