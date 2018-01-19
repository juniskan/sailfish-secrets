/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETSCRYPTO_CRYPTO_H
#define LIBSAILFISHSECRETSCRYPTO_CRYPTO_H

/* This file provides a C-compatible wrapper for Crypto */

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/****************************** Result ******************************/

enum Sailfish_Crypto_Result_Code {
	Sailfish_Crypto_Result_Succeeded = 0,
	Sailfish_Crypto_Result_Pending = 1,
	Sailfish_Crypto_Result_Failed = 2
};

struct Sailfish_Crypto_Result {
	enum Sailfish_Crypto_Result_Code code;
	int errorCode;
	int storageErrorCode;
	char *errorMessage;
	int refcount;
};

void Sailfish_Crypto_Result_ref(
		struct Sailfish_Crypto_Result *result);

void Sailfish_Crypto_Result_unref(
		struct Sailfish_Crypto_Result *result);

/****************************** Secret ******************************/

struct Sailfish_Crypto_Key_Identifier {
	char *name;
	char *collectionName;
	int refcount;
};

struct Sailfish_Crypto_Key_FilterDatum {
	char *field;
	char *value;
	struct Sailfish_Crypto_Key_FilterDatum *next;
};

struct Sailfish_Crypto_Key_CustomParameter {
	unsigned char *parameter;
	size_t parameterSize;
	struct Sailfish_Crypto_Key_CustomParameter *next;
};

enum Sailfish_Crypto_Key_Origin {
	Sailfish_Crypto_Key_OriginUnknown       = 0,
	Sailfish_Crypto_Key_OriginImported,
	Sailfish_Crypto_Key_OriginDevice,
	Sailfish_Crypto_Key_OriginSecureDevice
};

enum Sailfish_Crypto_Key_Algorithm {
	Sailfish_Crypto_Key_AlgorithmUnknown    = 0,

	Sailfish_Crypto_Key_Aes128              = 10,
	Sailfish_Crypto_Key_Aes196,
	Sailfish_Crypto_Key_Aes256,

	Sailfish_Crypto_Key_Dsa512              = 20,
	Sailfish_Crypto_Key_Dsa1024,
	Sailfish_Crypto_Key_Dsa2048,
	Sailfish_Crypto_Key_Dsa3072,
	Sailfish_Crypto_Key_Dsa4096,

	Sailfish_Crypto_Key_Rsa512              = 30,
	Sailfish_Crypto_Key_Rsa1028,
	Sailfish_Crypto_Key_Rsa2048,
	Sailfish_Crypto_Key_Rsa3072,
	Sailfish_Crypto_Key_Rsa4096,

	Sailfish_Crypto_Key_NistEcc192          = 40,
	Sailfish_Crypto_Key_NistEcc224,
	Sailfish_Crypto_Key_NistEcc256,
	Sailfish_Crypto_Key_NistEcc384,
	Sailfish_Crypto_Key_NistEcc521,

	Sailfish_Crypto_Key_BpEcc160            = 50,
	Sailfish_Crypto_Key_BpEcc192,
	Sailfish_Crypto_Key_BpEcc224,
	Sailfish_Crypto_Key_BpEcc256,
	Sailfish_Crypto_Key_BpEcc320,
	Sailfish_Crypto_Key_BpEcc384,
	Sailfish_Crypto_Key_BpEcc512
};

enum Sailfish_Crypto_Key_BlockMode {
	Sailfish_Crypto_Key_BlockModeUnknown    = 0,
	Sailfish_Crypto_Key_BlockModeCBC        = 1,
	Sailfish_Crypto_Key_BlockModeCTR        = 2,
	Sailfish_Crypto_Key_BlockModeECB        = 4,
	Sailfish_Crypto_Key_BlockModeGCM        = 8
};

enum Sailfish_Crypto_Key_EncryptionPadding {
	Sailfish_Crypto_Key_EncryptionPaddingUnknown    = 0,
	Sailfish_Crypto_Key_EncryptionPaddingNone       = 1,
	Sailfish_Crypto_Key_EncryptionPaddingPkcs7      = 2,
	Sailfish_Crypto_Key_EncryptionPaddingRsaOaep    = 4,
	Sailfish_Crypto_Key_EncryptionPaddingRsaOaepMgf1= 8,
	Sailfish_Crypto_Key_EncryptionPaddingRsaPkcs1   = 16,
	Sailfish_Crypto_Key_EncryptionPaddingAnsiX923   = 32
};

enum Sailfish_Crypto_Key_SignaturePadding {
	Sailfish_Crypto_Key_SignaturePaddingUnknown     = 0,
	Sailfish_Crypto_Key_SignaturePaddingNone        = 1,
	Sailfish_Crypto_Key_SignaturePaddingRsaPss      = 2,
	Sailfish_Crypto_Key_SignaturePaddingRsaPkcs1    = Sailfish_Crypto_Key_EncryptionPaddingRsaPkcs1,
	Sailfish_Crypto_Key_SignaturePaddingAnsiX923    = Sailfish_Crypto_Key_EncryptionPaddingAnsiX923
};

enum Sailfish_Crypto_Key_Digest {
	Sailfish_Crypto_Key_DigestUnknown       = 0,
	Sailfish_Crypto_Key_DigestSha1          = 1,
	Sailfish_Crypto_Key_DigestSha256        = 2,
	Sailfish_Crypto_Key_DigestSha384        = 4,
	Sailfish_Crypto_Key_DigestSha512        = 8
};

enum Sailfish_Crypto_Key_Operation {
	Sailfish_Crypto_Key_OperationUnknown    = 0,
	Sailfish_Crypto_Key_Sign                = 1,
	Sailfish_Crypto_Key_Verify              = 2,
	Sailfish_Crypto_Key_Encrypt             = 4,
	Sailfish_Crypto_Key_Decrypt             = 8
};

struct Sailfish_Crypto_Key {
	struct Sailfish_Crypto_Key_Identifier *identifier;

	enum Sailfish_Crypto_Key_Origin origin;
	enum Sailfish_Crypto_Key_Algorithm algorithm;
	int blockModes;
	int encryptionPaddings;
	int signaturePaddings;
	int digests;
	int operations;

	unsigned char *secretKey;
	size_t secretKeySize;
	unsigned char *publicKey;
	size_t publicKeySize;
	unsigned char *privateKey;
	size_t privateKeySize;

	time_t validityStart;
	time_t validityEnd;

	struct Sailfish_Crypto_Key_CustomParameter *customParameters;
	struct Sailfish_Crypto_Key_FilterDatum *filterData;

	int refcount;
};

struct Sailfish_Crypto_Key_Identifier*
Sailfish_Crypto_Key_Identifier_new(
		const char *name,
		const char *collectionName);

void Sailfish_Crypto_Key_Identifier_ref(
		struct Sailfish_Crypto_Key_Identifier *ident);

void Sailfish_Crypto_Key_Identifier_unref(
		struct Sailfish_Crypto_Key_Identifier *ident);

struct Sailfish_Crypto_Key_FilterDatum*
Sailfish_Crypto_Key_FilterDatum_new(
		const char *field,
		const char *value);

void Sailfish_Crypto_Key_FilterDatum_ref(
		struct Sailfish_Crypto_Key_FilterDatum *filter);

void Sailfish_Crypto_Key_FilterDatum_unref(
		struct Sailfish_Crypto_Key_FilterDatum *filter);

struct Sailfish_Crypto_Key_CustomParameter*
Sailfish_Crypto_Key_CustomParameter_new(
		const unsigned char *parameter,
		size_t parameterSize);

void Sailfish_Crypto_Key_CustomParameter_unref(
		struct Sailfish_Crypto_Key_CustomParameter *param);

struct Sailfish_Crypto_Key*
Sailfish_Crypto_Key_new(
		const char *name,
		const char *collectionName);

void Sailfish_Crypto_Key_ref(
		struct Sailfish_Crypto_Key *key);

void Sailfish_Crypto_Key_unref(
		struct Sailfish_Crypto_Key *key);

void Sailfish_Crypto_Key_setPrivateKey(
		struct Sailfish_Crypto_Key *key,
		const unsigned char *privateKey,
		size_t privateKeySize);

void Sailfish_Crypto_Key_setPublicKey(
		struct Sailfish_Crypto_Key *key,
		const unsigned char *publicKey,
		size_t publicKeySize);

void Sailfish_Crypto_Key_setSecretKey(
		struct Sailfish_Crypto_Key *key,
		const unsigned char *secretKey,
		size_t secretKeySize);

void Sailfish_Crypto_Key_addFilter(
		struct Sailfish_Crypto_Key *key,
		const char *field,
		const char *value);

void Sailfish_Crypto_Key_addCustomParameter(
		struct Sailfish_Crypto_Key *key,
		const unsigned char *parameter,
		size_t parameterSize);

/****************************** Crypto Manager ******************************/

typedef void (*Sailfish_Crypto_CryptoManager_generateKey_callback)
		(void *context, struct Sailfish_Crypto_Result *result, struct Sailfish_Crypto_Key *key);
typedef void (*Sailfish_Crypto_CryptoManager_generateStoredKey_callback)
		(void *context, struct Sailfish_Crypto_Result *result, struct Sailfish_Crypto_Key *keyReference);
typedef void (*Sailfish_Crypto_CryptoManager_storedKey_callback)
		(void *context, struct Sailfish_Crypto_Result *result, struct Sailfish_Crypto_Key *key);
typedef void (*Sailfish_Crypto_CryptoManager_deleteStoredKey_callback)
		(void *context, struct Sailfish_Crypto_Result *result);
typedef void (*Sailfish_Crypto_CryptoManager_sign_callback)
		(void *context, struct Sailfish_Crypto_Result *result, unsigned char *signature, size_t signatureSize);
typedef void (*Sailfish_Crypto_CryptoManager_verify_callback)
		(void *context, struct Sailfish_Crypto_Result *result, int verified);
typedef void (*Sailfish_Crypto_CryptoManager_encrypt_callback)
		(void *context, struct Sailfish_Crypto_Result *result, unsigned char *ciphertext, size_t ciphertextSize);
typedef void (*Sailfish_Crypto_CryptoManager_decrypt_callback)
		(void *context, struct Sailfish_Crypto_Result *result, unsigned char *plaintext, size_t plaintextSize);

int Sailfish_Crypto_CryptoManager_generateKey(
		struct Sailfish_Crypto_Key *keyTemplate,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_generateKey_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_generateStoredKey(
		struct Sailfish_Crypto_Key *keyTemplate,
		const char *cryptosystemProviderName,
		const char *storageProviderName,
		Sailfish_Crypto_CryptoManager_generateStoredKey_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_storedKey(
		struct Sailfish_Crypto_Key_Identifier *ident,
		Sailfish_Crypto_CryptoManager_storedKey_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_deleteStoredKey(
		struct Sailfish_Crypto_Key_Identifier *ident,
		Sailfish_Crypto_CryptoManager_deleteStoredKey_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_sign(
		const unsigned char *data,
		size_t dataSize,
		struct Sailfish_Crypto_Key *key,
		enum Sailfish_Crypto_Key_SignaturePadding padding,
		enum Sailfish_Crypto_Key_Digest digest,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_sign_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_verify(
		const unsigned char *data,
		size_t dataSize,
		struct Sailfish_Crypto_Key *key,
		enum Sailfish_Crypto_Key_SignaturePadding padding,
		enum Sailfish_Crypto_Key_Digest digest,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_verify_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_encrypt(
		const unsigned char *data,
		size_t dataSize,
		struct Sailfish_Crypto_Key *key,
		enum Sailfish_Crypto_Key_BlockMode blockMode,
		enum Sailfish_Crypto_Key_EncryptionPadding padding,
		enum Sailfish_Crypto_Key_Digest digest,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_encrypt_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_decrypt(
		const unsigned char *data,
		size_t dataSize,
		struct Sailfish_Crypto_Key *key,
		enum Sailfish_Crypto_Key_BlockMode blockMode,
		enum Sailfish_Crypto_Key_EncryptionPadding padding,
		enum Sailfish_Crypto_Key_Digest digest,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_decrypt_callback callback,
		void *callback_context);

/****************************** Daemon Connection *******************/

typedef void (*Sailfish_Crypto_connectToServer_callback)
		(void *context, struct Sailfish_Crypto_Result *result);
typedef void (*Sailfish_Crypto_disconnectFromServer_callback)
		(void *context, struct Sailfish_Crypto_Result *result);

int Sailfish_Crypto_busy();

int Sailfish_Crypto_connectedToServer();

int Sailfish_Crypto_connectToServer(
		Sailfish_Crypto_connectToServer_callback callback,
		void *callback_context);

int Sailfish_Crypto_disconnectFromServer(
		Sailfish_Crypto_disconnectFromServer_callback callback,
		void *callback_context);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LIBSAILFISHSECRETSCRYPTO_CRYPTO_H */

