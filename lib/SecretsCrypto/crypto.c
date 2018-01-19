/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "crypto.h"

#include <glib.h>
#include <gio/gio.h>
#ifdef G_OS_UNIX
#include <gio/gunixfdlist.h>
#endif

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/******************************* Data-Type Methods **************************/

static struct Sailfish_Crypto_Result *Sailfish_Crypto_Result_new(
		enum Sailfish_Crypto_Result_Code code,
		int errorCode,
		int storageErrorCode,
		const char *errorMessage)
{
	struct Sailfish_Crypto_Result *result =
	    (struct Sailfish_Crypto_Result *)
	    malloc(sizeof(struct Sailfish_Crypto_Result));

	result->code = code;
	result->errorCode = errorCode;
	result->storageErrorCode = storageErrorCode;
	result->errorMessage = errorMessage ? strndup(errorMessage, 512) : NULL;
	result->refcount = 1;
	return result;
}

void Sailfish_Crypto_Result_ref(struct Sailfish_Crypto_Result *result)
{
	if (result)
		result->refcount = result->refcount + 1;
}

void Sailfish_Crypto_Result_unref(struct Sailfish_Crypto_Result *result)
{
	if (result) {
		result->refcount = result->refcount - 1;
		if (result->refcount == 0) {
			free(result->errorMessage);
			free(result);
		}
	}
}

struct Sailfish_Crypto_Key_Identifier *
Sailfish_Crypto_Key_Identifier_new(
		const char *name,
		const char *collectionName)
{
	struct Sailfish_Crypto_Key_Identifier *ident =
	    (struct Sailfish_Crypto_Key_Identifier *)
	    malloc(sizeof(struct Sailfish_Crypto_Key_Identifier));

	ident->name = name ? strndup(name, 512) : NULL;
	ident->collectionName = collectionName
	    ? strndup(collectionName, 512) : NULL;
	ident->refcount = 1;

	return ident;
}

void Sailfish_Crypto_Key_Identifier_ref(
		struct Sailfish_Crypto_Key_Identifier *ident)
{
	if (ident)
		ident->refcount = ident->refcount + 1;
}

void Sailfish_Crypto_Key_Identifier_unref(
		struct Sailfish_Crypto_Key_Identifier *ident)
{
	if (ident) {
		ident->refcount = ident->refcount - 1;
		if (ident->refcount == 0) {
			free(ident->name);
			free(ident->collectionName);
			free(ident);
		}
	}
}

struct Sailfish_Crypto_Key_FilterDatum *
Sailfish_Crypto_Key_FilterDatum_new(
		const char *field,
		const char *value)
{
	struct Sailfish_Crypto_Key_FilterDatum *filter =
	    (struct Sailfish_Crypto_Key_FilterDatum *)
	    malloc(sizeof(struct Sailfish_Crypto_Key_FilterDatum));

	filter->field = field ? strndup(field, 512) : NULL;
	filter->value = value ? strndup(value, 512) : NULL;
	filter->next = NULL;

	return filter;
}

void Sailfish_Crypto_Key_FilterDatum_unref(
		struct Sailfish_Crypto_Key_FilterDatum *filter)
{
	if (filter) {
		struct Sailfish_Crypto_Key_FilterDatum *curr = filter;
		struct Sailfish_Crypto_Key_FilterDatum *next = filter->next
		    ? filter->next : NULL;

		while (curr) {
			free(curr->field);
			free(curr->value);
			free(curr);
			curr = next;
			next = curr ? curr->next : NULL;
		}
	}
}

struct Sailfish_Crypto_Key_CustomParameter*
Sailfish_Crypto_Key_CustomParameter_new(
		const unsigned char *parameter,
		size_t parameterSize)
{
	struct Sailfish_Crypto_Key_CustomParameter *param =
	    (struct Sailfish_Crypto_Key_CustomParameter *)
	    malloc(sizeof(struct Sailfish_Crypto_Key_CustomParameter));

	if (parameter && parameterSize > 0) {
		param->parameter = (unsigned char *)malloc(parameterSize);
		memcpy(param->parameter, parameter, parameterSize);
		param->parameterSize = parameterSize;
		param->next = NULL;
	} else {
		param->parameter = NULL;
		param->parameterSize = 0;
		param->next = NULL;
	}

	return param;
}

void Sailfish_Crypto_Key_CustomParameter_unref(
		struct Sailfish_Crypto_Key_CustomParameter *param)
{
	if (param) {
		struct Sailfish_Crypto_Key_CustomParameter *next = param->next;
		free(param->parameter);
		free(param);
		if (next) {
			Sailfish_Crypto_Key_CustomParameter_unref(next);
		}
	}
}

struct Sailfish_Crypto_Key*
Sailfish_Crypto_Key_new(
		const char *name,
		const char *collectionName)
{
	struct Sailfish_Crypto_Key* key =
	    (struct Sailfish_Crypto_Key*)malloc(
	    sizeof(struct Sailfish_Crypto_Key));

	key->identifier = Sailfish_Crypto_Key_Identifier_new(
		name, collectionName);

	key->secretKey = NULL;
	key->publicKey = NULL;
	key->privateKey = NULL;
	key->customParameters = NULL;
	key->filterData = NULL;

	key->origin = Sailfish_Crypto_Key_OriginUnknown;
	key->algorithm = Sailfish_Crypto_Key_AlgorithmUnknown;
	key->blockModes = Sailfish_Crypto_Key_BlockModeUnknown;
	key->encryptionPaddings = Sailfish_Crypto_Key_EncryptionPaddingUnknown;
	key->signaturePaddings = Sailfish_Crypto_Key_SignaturePaddingUnknown;
	key->digests = Sailfish_Crypto_Key_DigestUnknown;
	key->operations = Sailfish_Crypto_Key_OperationUnknown;

	key->refcount = 1;

	return key;
}

void Sailfish_Crypto_Key_ref(
		struct Sailfish_Crypto_Key *key)
{
	if (key)
		key->refcount += 1;
}

void Sailfish_Crypto_Key_unref(
		struct Sailfish_Crypto_Key *key)
{
	if (key) {
		key->refcount -= 1;
		if (key->refcount == 0) {
			Sailfish_Crypto_Key_Identifier_unref(key->identifier);
			Sailfish_Crypto_Key_CustomParameter_unref(key->customParameters);
			Sailfish_Crypto_Key_FilterDatum_unref(key->filterData);
			free(key->secretKey);
			free(key->publicKey);
			free(key->privateKey);
			free(key);
		}
	}
}

void Sailfish_Crypto_Key_setPrivateKey(
		struct Sailfish_Crypto_Key *key,
		const unsigned char *privateKey,
		size_t privateKeySize)
{
	if (key) {
		free(key->privateKey);
		if (privateKeySize && privateKey) {
			key->privateKeySize = privateKeySize;
			key->privateKey = (unsigned char *)malloc(privateKeySize);
			memcpy(key->privateKey, privateKey, privateKeySize);
		} else {
			key->privateKeySize = 0;
			key->privateKey = NULL;
		}
	}
}

void Sailfish_Crypto_Key_setPublicKey(
		struct Sailfish_Crypto_Key *key,
		const unsigned char *publicKey,
		size_t publicKeySize)
{
	if (key) {
		free(key->publicKey);
		if (publicKeySize && publicKey) {
			key->publicKeySize = publicKeySize;
			key->publicKey = (unsigned char *)malloc(publicKeySize);
			memcpy(key->publicKey, publicKey, publicKeySize);
		} else {
			key->publicKeySize = 0;
			key->publicKey = NULL;
		}
	}
}

void Sailfish_Crypto_Key_setSecretKey(
		struct Sailfish_Crypto_Key *key,
		const unsigned char *secretKey,
		size_t secretKeySize)
{
	if (key) {
		free(key->secretKey);
		if (secretKeySize && secretKey) {
			key->secretKeySize = secretKeySize;
			key->secretKey = (unsigned char *)malloc(secretKeySize);
			memcpy(key->secretKey, secretKey, secretKeySize);
		} else {
			key->secretKeySize = 0;
			key->secretKey = NULL;
		}
	}
}

void Sailfish_Crypto_Key_addFilter(
		struct Sailfish_Crypto_Key *key,
		const char *field,
		const char *value)
{
	if (key && field && value) {
		if (!key->filterData) {
			key->filterData = Sailfish_Crypto_Key_FilterDatum_new(
				    field, value);
		} else {
			struct Sailfish_Crypto_Key_FilterDatum *filter =
				    key->filterData;
			while (filter->next) {
				filter = filter->next;
			}
			filter->next = Sailfish_Crypto_Key_FilterDatum_new(
				    field, value);
		}
	}
}

void Sailfish_Crypto_Key_addCustomParameter(
		struct Sailfish_Crypto_Key *key,
		const unsigned char *parameter,
		size_t parameterSize)
{
	if (key && parameter && parameterSize) {
		if (!key->customParameters) {
			key->customParameters = Sailfish_Crypto_Key_CustomParameter_new(
				    parameter, parameterSize);
		} else {
			struct Sailfish_Crypto_Key_CustomParameter *param =
				    key->customParameters;
			while (param->next) {
				param = param->next;
			}
			param->next = Sailfish_Crypto_Key_CustomParameter_new(
				    parameter, parameterSize);
		}
	}
}

/******************************* Internal Callback Wrapping *****************/

typedef void (*Sailfish_Crypto_CryptoManager_result_callback) (
		void *context, struct Sailfish_Crypto_Result *result);
typedef void (*Sailfish_Crypto_CryptoManager_key_result_callback) (
		void *context, struct Sailfish_Crypto_Result *result,
		struct Sailfish_Crypto_Key *key);
typedef void (*Sailfish_Crypto_CryptoManager_data_result_callback) (
		void *context, struct Sailfish_Crypto_Result *result,
		const unsigned char *data, size_t dataSize);
typedef void (*Sailfish_Crypto_CryptoManager_bool_result_callback) (
		void *context, struct Sailfish_Crypto_Result *result,
		int booleanValue);

struct Sailfish_Crypto_Callback_Data {
	Sailfish_Crypto_CryptoManager_result_callback result_callback;
	Sailfish_Crypto_CryptoManager_key_result_callback
	    key_result_callback;
	Sailfish_Crypto_CryptoManager_data_result_callback
	    data_result_callback;
	Sailfish_Crypto_CryptoManager_bool_result_callback
	    bool_result_callback;
	void *callback_context;
	int refcount;
};

struct Sailfish_Crypto_Callback_Data *
Sailfish_Crypto_Callback_Data_new(
		Sailfish_Crypto_CryptoManager_result_callback rc,
		Sailfish_Crypto_CryptoManager_key_result_callback krc,
		Sailfish_Crypto_CryptoManager_data_result_callback drc,
		Sailfish_Crypto_CryptoManager_bool_result_callback brc,
		void *cc)
{
	struct Sailfish_Crypto_Callback_Data *cbd =
	    (struct Sailfish_Crypto_Callback_Data *)
	    malloc(sizeof(struct Sailfish_Crypto_Callback_Data));

	cbd->result_callback = rc;
	cbd->key_result_callback = krc;
	cbd->data_result_callback = drc;
	cbd->bool_result_callback = brc;
	cbd->callback_context = cc;
	cbd->refcount = 1;

	return cbd;
}

void Sailfish_Crypto_Callback_Data_ref(
		struct Sailfish_Crypto_Callback_Data *cbd)
{
	cbd->refcount = cbd->refcount + 1;
}

void Sailfish_Crypto_Callback_Data_unref(
		struct Sailfish_Crypto_Callback_Data *cbd)
{
	if (cbd) {
		cbd->refcount = cbd->refcount - 1;
		if (cbd->refcount == 0)
			free(cbd);
	}
}

/******************************* Internal Daemon Connection *****************/

static struct Sailfish_Crypto_DBus_Connection {
	GDBusProxy *discoveryProxy;
	char *p2pAddr;
	GDBusConnection *p2pBus;
	GDBusProxy *cryptoProxy;
	int busy;
} daemon_connection = {
	.discoveryProxy = NULL,
	.p2pAddr = NULL,
	.p2pBus = NULL,
	.cryptoProxy = NULL,
	.busy = 0
};

void Sailfish_Crypto_proxyReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GDBusProxy *proxy = g_dbus_proxy_new_finish(res, NULL);
	(void)source_object;
	if (proxy) {
		/* Success, we're connected! */
		struct Sailfish_Crypto_Result *result =
		    Sailfish_Crypto_Result_new
		    (Sailfish_Crypto_Result_Succeeded, 0, 0, "");
		struct Sailfish_Crypto_Callback_Data *cbd =
		    (struct Sailfish_Crypto_Callback_Data *)user_data;
		daemon_connection.cryptoProxy = proxy;
		daemon_connection.busy = 0;
		cbd->result_callback(cbd->callback_context, result);
		Sailfish_Crypto_Result_unref(result);
		Sailfish_Crypto_Callback_Data_unref(cbd);
	} else {
		struct Sailfish_Crypto_Result *result =
		    Sailfish_Crypto_Result_new(
				    Sailfish_Crypto_Result_Failed,
				    5,
				    0,
				    "Unable to create crypto interface");
		struct Sailfish_Crypto_Callback_Data *cbd =
		    (struct Sailfish_Crypto_Callback_Data *)user_data;
		g_dbus_connection_close_sync(daemon_connection.p2pBus, NULL,
					     NULL);
		g_object_unref(daemon_connection.p2pBus);
		daemon_connection.p2pBus = NULL;
		daemon_connection.busy = 0;
		cbd->result_callback(cbd->callback_context, result);
		Sailfish_Crypto_Result_unref(result);
		Sailfish_Crypto_Callback_Data_unref(cbd);
	}
}

void Sailfish_Crypto_connectionReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	daemon_connection.p2pBus =
	    g_dbus_connection_new_for_address_finish(res, NULL);
	(void)source_object;
	if (daemon_connection.p2pBus) {
		free(daemon_connection.p2pAddr);
		daemon_connection.p2pAddr = NULL;
		g_dbus_proxy_new(
		    daemon_connection.p2pBus,
		    G_DBUS_PROXY_FLAGS_NONE,
		    NULL,
		    NULL, /* bus name */
		    "/Sailfish/Crypto",
		    "org.sailfishos.crypto",
		    NULL, /* GCancellable */
		    Sailfish_Crypto_proxyReady,
		    user_data);
	} else {
		struct Sailfish_Crypto_Result *result =
		    Sailfish_Crypto_Result_new(
				    Sailfish_Crypto_Result_Failed,
				    5,
				    0,
				    "Unable to connect to crypto daemon bus");
		struct Sailfish_Crypto_Callback_Data *cbd =
		    (struct Sailfish_Crypto_Callback_Data *)user_data;
		free(daemon_connection.p2pAddr);
		daemon_connection.p2pAddr = NULL;
		daemon_connection.busy = 0;
		cbd->result_callback(cbd->callback_context, result);
		Sailfish_Crypto_Result_unref(result);
		Sailfish_Crypto_Callback_Data_unref(cbd);
	}
}

void Sailfish_Crypto_peerToPeerAddressReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GVariant *p2pAddrResult =
	    g_dbus_proxy_call_finish(daemon_connection.discoveryProxy, res,
				     NULL);
	(void)source_object;
	if (p2pAddrResult) {
		g_variant_get(p2pAddrResult, "(s)", &daemon_connection.p2pAddr);
		g_variant_unref(p2pAddrResult);
	}
	g_object_unref(daemon_connection.discoveryProxy);
	daemon_connection.discoveryProxy = NULL;
	if (daemon_connection.p2pAddr) {
		/* We have discovered the p2p bus address of crypto API */
		g_dbus_connection_new_for_address(
		    daemon_connection.p2pAddr,
		    G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
		    NULL, /* observer */
		    NULL, /* cancellable */
		    Sailfish_Crypto_connectionReady,
		    user_data);
	} else {
		struct Sailfish_Crypto_Result *result =
		    Sailfish_Crypto_Result_new(
				    Sailfish_Crypto_Result_Failed,
				    6,
				    0,
				    "Unable to discover crypto daemon bus");
		struct Sailfish_Crypto_Callback_Data *cbd =
		    (struct Sailfish_Crypto_Callback_Data *)user_data;
		daemon_connection.busy = 0;
		cbd->result_callback(cbd->callback_context, result);
		Sailfish_Crypto_Result_unref(result);
		Sailfish_Crypto_Callback_Data_unref(cbd);
	}
}

void Sailfish_Crypto_discoveryProxyReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GDBusProxy *discoveryProxy = g_dbus_proxy_new_for_bus_finish(res, NULL);
	daemon_connection.discoveryProxy = discoveryProxy;
	(void)source_object;
	if (discoveryProxy) {
		g_dbus_proxy_call(
		    discoveryProxy,
		    "peerToPeerAddress",
		    g_variant_new("()"),
		    G_DBUS_CALL_FLAGS_NONE,
		    -1,
		    NULL, /* GCancellable */
		    Sailfish_Crypto_peerToPeerAddressReady,
		    user_data);
	} else {
		struct Sailfish_Crypto_Result *result =
		    Sailfish_Crypto_Result_new(
				    Sailfish_Crypto_Result_Failed,
				    6,
				    0,
				    "Unable to connect to crypto daemon discovery service");
		struct Sailfish_Crypto_Callback_Data *cbd =
		    (struct Sailfish_Crypto_Callback_Data *)user_data;
		g_object_unref(daemon_connection.discoveryProxy);
		daemon_connection.discoveryProxy = NULL;
		daemon_connection.busy = 0;
		cbd->result_callback(cbd->callback_context, result);
		Sailfish_Crypto_Result_unref(result);
		Sailfish_Crypto_Callback_Data_unref(cbd);
	}
}

void Sailfish_Crypto_disconnectReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GError *error = NULL;
	(void)source_object;
	if (g_dbus_connection_close_finish(
			daemon_connection.p2pBus, res, &error)) {
		struct Sailfish_Crypto_Result *result =
		    Sailfish_Crypto_Result_new
		    (Sailfish_Crypto_Result_Succeeded, 0, 0, "");
		struct Sailfish_Crypto_Callback_Data *cbd =
		    (struct Sailfish_Crypto_Callback_Data *)user_data;
		g_object_unref(daemon_connection.cryptoProxy);
		daemon_connection.cryptoProxy = NULL;
		g_object_unref(daemon_connection.p2pBus);
		daemon_connection.p2pBus = NULL;
		daemon_connection.busy = 0;
		cbd->result_callback(cbd->callback_context, result);
		Sailfish_Crypto_Result_unref(result);
		Sailfish_Crypto_Callback_Data_unref(cbd);
	} else {
		/* check to see if the error was that the connection was already closed */
		if (error->code == G_IO_ERROR_CLOSED) {
			struct Sailfish_Crypto_Result *result =
			    Sailfish_Crypto_Result_new
			    (Sailfish_Crypto_Result_Succeeded, 0, 0, "");
			struct Sailfish_Crypto_Callback_Data *cbd =
			    (struct Sailfish_Crypto_Callback_Data *)user_data;
			g_object_unref(daemon_connection.cryptoProxy);
			daemon_connection.cryptoProxy = NULL;
			g_object_unref(daemon_connection.p2pBus);
			daemon_connection.p2pBus = NULL;
			daemon_connection.busy = 0;
			cbd->result_callback(cbd->callback_context, result);
			Sailfish_Crypto_Result_unref(result);
			Sailfish_Crypto_Callback_Data_unref(cbd);
		} else {
			struct Sailfish_Crypto_Result *result =
			    Sailfish_Crypto_Result_new
			    (Sailfish_Crypto_Result_Failed, 2, 0,
			     "Unable to disconnect from the crypto daemon");
			struct Sailfish_Crypto_Callback_Data *cbd =
			    (struct Sailfish_Crypto_Callback_Data *)user_data;
			daemon_connection.busy = 0;
			cbd->result_callback(cbd->callback_context, result);
			Sailfish_Crypto_Result_unref(result);
			Sailfish_Crypto_Callback_Data_unref(cbd);
		}
		g_error_free(error);
	}
}

/******************************* Internal DBus Marshalling ******************/

GVariant *Sailfish_Crypto_variantFromKeyIdentifier(
		struct Sailfish_Crypto_Key_Identifier *ident)
{
	return g_variant_new("(ss)", ident->name, ident->collectionName);
}

GVariant *Sailfish_Crypto_variantFromByteArray(
		const unsigned char *data, size_t dataSize)
{
	GVariant *result = NULL;
	unsigned char *dataCopy = NULL;
	GByteArray *persistent = NULL;
	if (data && dataSize) {
		dataCopy = (unsigned char *)malloc(
			    dataSize * sizeof(unsigned char));
		memcpy(dataCopy, data, dataSize);
		persistent = g_byte_array_new_take(
			    dataCopy,
			    dataSize);
	} else {
		persistent = g_byte_array_new();
	}
	result = g_variant_new_from_data(
		    G_VARIANT_TYPE ("ay"),
		    persistent->data,
		    persistent->len * sizeof(unsigned char),
		    TRUE,
		    (GDestroyNotify)g_byte_array_unref,
		    g_byte_array_ref(persistent));
	g_byte_array_unref(persistent);
	return result;
}

const unsigned char *Sailfish_Crypto_byteArrayFromVariant(
		GVariant *variant, size_t *dataSize)
{
	return g_variant_get_fixed_array(
		    variant,
		    dataSize,
		    sizeof(unsigned char));
}

GVariant *Sailfish_Crypto_variantFromKey(
		struct Sailfish_Crypto_Key *key)
{
	GVariant *result = NULL;
	GVariantBuilder *customParametersBuilder = NULL;
	GVariantBuilder *filterDataBuilder = NULL;
	struct Sailfish_Crypto_Key_CustomParameter *customParam = NULL;
	struct Sailfish_Crypto_Key_FilterDatum *currFilter = NULL;

	if (key == NULL)
		return NULL;

	customParam = key->customParameters;
	customParametersBuilder = g_variant_builder_new(G_VARIANT_TYPE("aay"));
	while (customParam) {
		g_variant_builder_add(customParametersBuilder,
			    "ay",
			    Sailfish_Crypto_variantFromByteArray(
				    customParam->parameter,
				    customParam->parameterSize));
		customParam = customParam->next;
	}

	filterDataBuilder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	currFilter = key->filterData;
	while (currFilter) {
		g_variant_builder_add(filterDataBuilder, "{sv}",
				    currFilter->field,
				    g_variant_new("s", currFilter->value));
		currFilter = currFilter->next;
	}

	result = g_variant_new(
			    "((ss)iiiiiii@ay@ay@ayii@aay(@a{sv}))",
			    key->identifier->name,
			    key->identifier->collectionName,
			    key->origin,
			    key->algorithm,
			    key->operations,
			    key->blockModes,
			    key->encryptionPaddings,
			    key->signaturePaddings,
			    key->digests,
			    Sailfish_Crypto_variantFromByteArray(
				    key->publicKey, key->publicKeySize),
			    Sailfish_Crypto_variantFromByteArray(
				    key->privateKey, key->privateKeySize),
			    Sailfish_Crypto_variantFromByteArray(
				    key->secretKey, key->secretKeySize),
			    key->validityStart,
			    key->validityEnd,
			    g_variant_builder_end(customParametersBuilder),
			    g_variant_builder_end(filterDataBuilder));

	g_variant_builder_unref(customParametersBuilder);
	g_variant_builder_unref(filterDataBuilder);

	return result;
}

struct Sailfish_Crypto_Key *
Sailfish_Crypto_keyFromVariant(GVariant *variant)
{
	struct Sailfish_Crypto_Key *key = NULL;
	char *keyName = NULL;
	char *collectionName = NULL;
	int origin = 0;
	int algorithm = 0;
	int operations = 0;
	int blockModes = 0;
	int encryptionPaddings = 0;
	int signaturePaddings = 0;
	int digests = 0;
	GVariant *publicKeyVariant = NULL;
	GVariant *privateKeyVariant = NULL;
	GVariant *secretKeyVariant = NULL;
	time_t validityStart = 0;
	time_t validityEnd = 0;
	GVariantIter *customParamIter = NULL;
    GVariant *customParam = NULL;
	GVariantIter *filterIter = NULL;
	char *field = NULL;
	GVariant *value = NULL;

	g_variant_get(
		    variant, "((ss)iiiiiii@ay@ay@ayiiaay(a{sv}))",
		    &keyName,
		    &collectionName,
		    &origin,
		    &algorithm,
		    &operations,
		    &blockModes,
		    &encryptionPaddings,
		    &signaturePaddings,
		    &digests,
		    &publicKeyVariant,
		    &privateKeyVariant,
		    &secretKeyVariant,
		    &validityStart,
		    &validityEnd,
		    &customParamIter,
		    &filterIter);

	key = Sailfish_Crypto_Key_new(keyName, collectionName);
	key->origin = origin;
	key->algorithm = algorithm;
	key->operations = operations;
	key->blockModes = blockModes;
	key->encryptionPaddings = encryptionPaddings;
	key->signaturePaddings = signaturePaddings;
	key->digests = digests;

	if (publicKeyVariant) {
		size_t keySize = 0;
		const unsigned char *keyData =
			    Sailfish_Crypto_byteArrayFromVariant(
				    publicKeyVariant, &keySize);
		if (keySize && keyData) {
			Sailfish_Crypto_Key_setPublicKey(
				    key, keyData, keySize);
		}
	}

	if (privateKeyVariant) {
		size_t keySize = 0;
		const unsigned char *keyData =
			    Sailfish_Crypto_byteArrayFromVariant(
				    privateKeyVariant, &keySize);
		if (keySize && keyData) {
			Sailfish_Crypto_Key_setPrivateKey(
				    key, keyData, keySize);
		}
	}

	if (secretKeyVariant) {
		size_t keySize = 0;
		const unsigned char *keyData =
			    Sailfish_Crypto_byteArrayFromVariant(
				    secretKeyVariant, &keySize);
		if (keySize && keyData) {
			Sailfish_Crypto_Key_setSecretKey(
				    key, keyData, keySize);
		}
	}

	key->validityStart = validityStart;
	key->validityEnd = validityEnd;

	while (customParamIter && g_variant_iter_next(
		    customParamIter, "ay", &customParam)) {
		size_t paramSize = 0;
		const unsigned char *paramData =
			    Sailfish_Crypto_byteArrayFromVariant(
				    customParam, &paramSize);
		if (paramSize && paramData) {
			Sailfish_Crypto_Key_addCustomParameter(
				    key,
				    paramData,
				    paramSize);
		}
		g_variant_unref(customParam);
	}

	while (filterIter && g_variant_iter_next(
		    filterIter, "{sv}", &field, &value)) {
		if (field && value) {
			Sailfish_Crypto_Key_addFilter(
				    key,
				    field,
				    g_variant_get_string(value, NULL));
		}
		g_variant_unref(value);
		g_free(field);
	}

	if (customParamIter)
		g_variant_iter_free(customParamIter);
	if (filterIter)
		g_variant_iter_free(filterIter);
	g_variant_unref(publicKeyVariant);
	g_variant_unref(privateKeyVariant);
	g_variant_unref(secretKeyVariant);
	g_free(collectionName);
	g_free(keyName);

	return key;
}

/******************************* Internal Crypto Manager ********************/

void Sailfish_Crypto_generateKeyReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	struct Sailfish_Crypto_Result *result = NULL;
	struct Sailfish_Crypto_Key *keyResult = NULL;
	struct Sailfish_Crypto_Callback_Data *cbd =
	    (struct Sailfish_Crypto_Callback_Data *)user_data;
	GVariant *daemon_result =
	    g_dbus_proxy_call_finish(daemon_connection.cryptoProxy, res, NULL);
	(void)source_object;
	if (daemon_result) {
		int resultCode = 0;
		int errorCode = 0;
		int storageErrorCode = 0;
		gchar *errorMessage = NULL;
		GVariant *keyVariant = NULL;
		g_variant_get(
		    daemon_result, "((iiis)@*)",
		    &resultCode,
		    &errorCode,
		    &storageErrorCode,
		    &errorMessage,
		    &keyVariant);
		keyResult = Sailfish_Crypto_keyFromVariant(keyVariant);
		result = Sailfish_Crypto_Result_new(
		    resultCode,
		    errorCode,
		    storageErrorCode,
		    errorMessage);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
	} else {
		result = Sailfish_Crypto_Result_new(
		    Sailfish_Crypto_Result_Failed,
		    5,
		    0,
		    "Unable to finish generate key call");
	}

	daemon_connection.busy = 0;
	cbd->key_result_callback(cbd->callback_context, result, keyResult);
	Sailfish_Crypto_Result_unref(result);
	free(cbd);
}

void Sailfish_Crypto_generateStoredKeyReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	struct Sailfish_Crypto_Result *result = NULL;
	struct Sailfish_Crypto_Key *keyResult = NULL;
	struct Sailfish_Crypto_Callback_Data *cbd =
	    (struct Sailfish_Crypto_Callback_Data *)user_data;
	GVariant *daemon_result =
	    g_dbus_proxy_call_finish(daemon_connection.cryptoProxy, res, NULL);
	(void)source_object;
	if (daemon_result) {
		int resultCode = 0;
		int errorCode = 0;
		int storageErrorCode = 0;
		gchar *errorMessage = NULL;
		GVariant *keyVariant = NULL;
		g_variant_get(
		    daemon_result, "((iiis)@*)",
		    &resultCode,
		    &errorCode,
		    &storageErrorCode,
		    &errorMessage,
		    &keyVariant);
		keyResult = Sailfish_Crypto_keyFromVariant(keyVariant);
		result = Sailfish_Crypto_Result_new(
		    resultCode,
		    errorCode,
		    storageErrorCode,
		    errorMessage);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
	} else {
		result = Sailfish_Crypto_Result_new(
		    Sailfish_Crypto_Result_Failed,
		    5,
		    0,
		    "Unable to finish generate stored key call");
	}

	daemon_connection.busy = 0;
	cbd->key_result_callback(cbd->callback_context, result, keyResult);
	Sailfish_Crypto_Result_unref(result);
	free(cbd);
}

void Sailfish_Crypto_storedKeyReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	struct Sailfish_Crypto_Result *result = NULL;
	struct Sailfish_Crypto_Key *keyResult = NULL;
	struct Sailfish_Crypto_Callback_Data *cbd =
	    (struct Sailfish_Crypto_Callback_Data *)user_data;
	GVariant *daemon_result =
	    g_dbus_proxy_call_finish(daemon_connection.cryptoProxy, res, NULL);
	(void)source_object;
	if (daemon_result) {
		int resultCode = 0;
		int errorCode = 0;
		int storageErrorCode = 0;
		gchar *errorMessage = NULL;
		GVariant *keyVariant = NULL;
		g_variant_get(
		    daemon_result, "((iiis)@*)",
		    &resultCode,
		    &errorCode,
		    &storageErrorCode,
		    &errorMessage,
		    &keyVariant);
		keyResult = Sailfish_Crypto_keyFromVariant(keyVariant);
		result = Sailfish_Crypto_Result_new(
		    resultCode,
		    errorCode,
		    storageErrorCode,
		    errorMessage);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
	} else {
		result = Sailfish_Crypto_Result_new(
		    Sailfish_Crypto_Result_Failed,
		    5,
		    0,
		    "Unable to finish stored key call");
	}

	daemon_connection.busy = 0;
	cbd->key_result_callback(cbd->callback_context, result, keyResult);
	Sailfish_Crypto_Result_unref(result);
	free(cbd);
}

void Sailfish_Crypto_deleteStoredKeyReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	struct Sailfish_Crypto_Result *result = NULL;
	struct Sailfish_Crypto_Callback_Data *cbd =
	    (struct Sailfish_Crypto_Callback_Data *)user_data;
	GVariant *daemon_result =
	    g_dbus_proxy_call_finish(daemon_connection.cryptoProxy, res, NULL);
	(void)source_object;
	if (daemon_result) {
		int resultCode = 0;
		int errorCode = 0;
		int storageErrorCode = 0;
		gchar *errorMessage = NULL;
		g_variant_get(
		    daemon_result, "((iiis))",
		    &resultCode,
		    &errorCode,
		    &storageErrorCode,
		    &errorMessage);
		result = Sailfish_Crypto_Result_new(
		    resultCode,
		    errorCode,
		    storageErrorCode,
		    errorMessage);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
	} else {
		result = Sailfish_Crypto_Result_new(
		    Sailfish_Crypto_Result_Failed,
		    5,
		    0,
		    "Unable to finish delete stored key call");
	}

	daemon_connection.busy = 0;
	cbd->result_callback(cbd->callback_context, result);
	Sailfish_Crypto_Result_unref(result);
	free(cbd);
}

void Sailfish_Crypto_signReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	struct Sailfish_Crypto_Result *result = NULL;
	const unsigned char *data = NULL;
	size_t dataSize = 0;
	struct Sailfish_Crypto_Callback_Data *cbd =
	    (struct Sailfish_Crypto_Callback_Data *)user_data;
	GVariant *daemon_result =
	    g_dbus_proxy_call_finish(daemon_connection.cryptoProxy, res, NULL);
	(void)source_object;
	if (daemon_result) {
		int resultCode = 0;
		int errorCode = 0;
		int storageErrorCode = 0;
		gchar *errorMessage = NULL;
		GVariant *dataVariant = NULL;
		g_variant_get(
		    daemon_result, "((iiis)@ay)",
		    &resultCode,
		    &errorCode,
		    &storageErrorCode,
		    &errorMessage,
		    &dataVariant);
		data = Sailfish_Crypto_byteArrayFromVariant(
		    dataVariant, &dataSize);
		result = Sailfish_Crypto_Result_new(
		    resultCode,
		    errorCode,
		    storageErrorCode,
		    errorMessage);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
	} else {
		result = Sailfish_Crypto_Result_new(
		    Sailfish_Crypto_Result_Failed,
		    5,
		    0,
		    "Unable to finish sign call");
	}

	daemon_connection.busy = 0;
	cbd->data_result_callback(
		    cbd->callback_context, result,
		    data, dataSize);
	Sailfish_Crypto_Result_unref(result);
	free(cbd);
}

void Sailfish_Crypto_verifyReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	struct Sailfish_Crypto_Result *result = NULL;
	gboolean verified = 0;
	struct Sailfish_Crypto_Callback_Data *cbd =
	    (struct Sailfish_Crypto_Callback_Data *)user_data;
	GVariant *daemon_result =
	    g_dbus_proxy_call_finish(daemon_connection.cryptoProxy, res, NULL);
	(void)source_object;
	if (daemon_result) {
		int resultCode = 0;
		int errorCode = 0;
		int storageErrorCode = 0;
		gchar *errorMessage = NULL;
		g_variant_get(
		    daemon_result, "((iiis)b)",
		    &resultCode,
		    &errorCode,
		    &storageErrorCode,
		    &errorMessage,
		    &verified);
		result = Sailfish_Crypto_Result_new(
		    resultCode,
		    errorCode,
		    storageErrorCode,
		    errorMessage);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
	} else {
		result = Sailfish_Crypto_Result_new(
		    Sailfish_Crypto_Result_Failed,
		    5,
		    0,
		    "Unable to finish verify call");
	}

	daemon_connection.busy = 0;
	cbd->bool_result_callback(
		    cbd->callback_context, result, verified);
	Sailfish_Crypto_Result_unref(result);
	free(cbd);
}

void Sailfish_Crypto_encryptReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	struct Sailfish_Crypto_Result *result = NULL;
	const unsigned char *data = NULL;
	size_t dataSize = 0;
	struct Sailfish_Crypto_Callback_Data *cbd =
	    (struct Sailfish_Crypto_Callback_Data *)user_data;
	GVariant *daemon_result =
	    g_dbus_proxy_call_finish(daemon_connection.cryptoProxy, res, NULL);
	(void)source_object;
	if (daemon_result) {
		int resultCode = 0;
		int errorCode = 0;
		int storageErrorCode = 0;
		gchar *errorMessage = NULL;
		GVariant *dataVariant = NULL;
		g_variant_get(
		    daemon_result, "((iiis)@ay)",
		    &resultCode,
		    &errorCode,
		    &storageErrorCode,
		    &errorMessage,
		    &dataVariant);
		data = Sailfish_Crypto_byteArrayFromVariant(
		    dataVariant, &dataSize);
		result = Sailfish_Crypto_Result_new(
		    resultCode,
		    errorCode,
		    storageErrorCode,
		    errorMessage);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
	} else {
		result = Sailfish_Crypto_Result_new(
		    Sailfish_Crypto_Result_Failed,
		    5,
		    0,
		    "Unable to finish encrypt call");
	}

	daemon_connection.busy = 0;
	cbd->data_result_callback(
		    cbd->callback_context, result,
		    data, dataSize);
	Sailfish_Crypto_Result_unref(result);
	free(cbd);
}

void Sailfish_Crypto_decryptReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	struct Sailfish_Crypto_Result *result = NULL;
	const unsigned char *data = NULL;
	size_t dataSize = 0;
	struct Sailfish_Crypto_Callback_Data *cbd =
	    (struct Sailfish_Crypto_Callback_Data *)user_data;
	GVariant *daemon_result =
	    g_dbus_proxy_call_finish(daemon_connection.cryptoProxy, res, NULL);
	(void)source_object;
	if (daemon_result) {
		int resultCode = 0;
		int errorCode = 0;
		int storageErrorCode = 0;
		gchar *errorMessage = NULL;
		GVariant *dataVariant = NULL;
		g_variant_get(
		    daemon_result, "((iiis)@ay)",
		    &resultCode,
		    &errorCode,
		    &storageErrorCode,
		    &errorMessage,
		    &dataVariant);
		data = Sailfish_Crypto_byteArrayFromVariant(
		    dataVariant, &dataSize);
		result = Sailfish_Crypto_Result_new(
		    resultCode,
		    errorCode,
		    storageErrorCode,
		    errorMessage);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
	} else {
		result = Sailfish_Crypto_Result_new(
		    Sailfish_Crypto_Result_Failed,
		    5,
		    0,
		    "Unable to finish decrypt call");
	}

	daemon_connection.busy = 0;
	cbd->data_result_callback(
		    cbd->callback_context, result,
		    data, dataSize);
	Sailfish_Crypto_Result_unref(result);
	free(cbd);
}

/******************************* Crypto Manager *****************************/

int Sailfish_Crypto_CryptoManager_generateKey(
		struct Sailfish_Crypto_Key *keyTemplate,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_generateKey_callback callback,
		void *callback_context)
{
	if (Sailfish_Crypto_busy() || !Sailfish_Crypto_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Crypto_Callback_Data *cbd =
		    Sailfish_Crypto_Callback_Data_new(
			    NULL,
			    (Sailfish_Crypto_CryptoManager_key_result_callback)callback,
			    NULL,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_call(daemon_connection.cryptoProxy,
				  "generateKey",
				  g_variant_new("(@((ss)iiiiiiiayayayiiaay(a{sv}))s)",
						Sailfish_Crypto_variantFromKey(keyTemplate),
						cryptosystemProviderName),
				  G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				  Sailfish_Crypto_generateKeyReady, cbd);
		return 1;
	}
}

int Sailfish_Crypto_CryptoManager_generateStoredKey(
		struct Sailfish_Crypto_Key *keyTemplate,
		const char *cryptosystemProviderName,
		const char *storageProviderName,
		Sailfish_Crypto_CryptoManager_generateStoredKey_callback callback,
		void *callback_context)
{
	if (Sailfish_Crypto_busy() || !Sailfish_Crypto_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Crypto_Callback_Data *cbd =
		    Sailfish_Crypto_Callback_Data_new(
			    NULL,
			    (Sailfish_Crypto_CryptoManager_key_result_callback)callback,
			    NULL,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_call(daemon_connection.cryptoProxy,
				  "generateStoredKey",
				  g_variant_new("(@((ss)iiiiiiiayayayiiaay(a{sv}))ss)",
						Sailfish_Crypto_variantFromKey(keyTemplate),
						cryptosystemProviderName,
						storageProviderName),
				  G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				  Sailfish_Crypto_generateStoredKeyReady, cbd);
		return 1;
	}
}

int Sailfish_Crypto_CryptoManager_storedKey(
		struct Sailfish_Crypto_Key_Identifier *ident,
		Sailfish_Crypto_CryptoManager_storedKey_callback callback,
		void *callback_context)
{
	if (Sailfish_Crypto_busy() || !Sailfish_Crypto_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Crypto_Callback_Data *cbd =
		    Sailfish_Crypto_Callback_Data_new(
			    NULL,
			    (Sailfish_Crypto_CryptoManager_key_result_callback)callback,
			    NULL,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_call(daemon_connection.cryptoProxy,
				  "storedKey",
				  g_variant_new("(@(ss))",
						Sailfish_Crypto_variantFromKeyIdentifier(ident)),
				  G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				  Sailfish_Crypto_storedKeyReady, cbd);
		return 1;
	}
}

int Sailfish_Crypto_CryptoManager_deleteStoredKey(
		struct Sailfish_Crypto_Key_Identifier *ident,
		Sailfish_Crypto_CryptoManager_deleteStoredKey_callback callback,
		void *callback_context)
{
	if (Sailfish_Crypto_busy() || !Sailfish_Crypto_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Crypto_Callback_Data *cbd =
		    Sailfish_Crypto_Callback_Data_new(
			    (Sailfish_Crypto_CryptoManager_result_callback)callback,
			    NULL,
			    NULL,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_call(daemon_connection.cryptoProxy,
				  "deleteStoredKey",
				  g_variant_new("(@(ss))",
						Sailfish_Crypto_variantFromKeyIdentifier(ident)),
				  G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				  Sailfish_Crypto_deleteStoredKeyReady, cbd);
		return 1;
	}
}

int Sailfish_Crypto_CryptoManager_sign(
		const unsigned char *data,
		size_t dataSize,
		struct Sailfish_Crypto_Key *key,
		enum Sailfish_Crypto_Key_SignaturePadding padding,
		enum Sailfish_Crypto_Key_Digest digest,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_sign_callback callback,
		void *callback_context)
{
	if (Sailfish_Crypto_busy() || !Sailfish_Crypto_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Crypto_Callback_Data *cbd =
		    Sailfish_Crypto_Callback_Data_new(
			    NULL,
			    NULL,
			    (Sailfish_Crypto_CryptoManager_data_result_callback)callback,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_call(daemon_connection.cryptoProxy,
				  "sign",
				  g_variant_new("(@ay@((ss)iiiiiiiayayayiiaay(a{sv}))(i)(i)s)",
						Sailfish_Crypto_variantFromByteArray(data, dataSize),
						Sailfish_Crypto_variantFromKey(key),
						(int)padding,
						(int)digest,
						cryptosystemProviderName),
				  G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				  Sailfish_Crypto_signReady, cbd);
		return 1;
	}
}

int Sailfish_Crypto_CryptoManager_verify(
		const unsigned char *data,
		size_t dataSize,
		struct Sailfish_Crypto_Key *key,
		enum Sailfish_Crypto_Key_SignaturePadding padding,
		enum Sailfish_Crypto_Key_Digest digest,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_verify_callback callback,
		void *callback_context)
{
	if (Sailfish_Crypto_busy() || !Sailfish_Crypto_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Crypto_Callback_Data *cbd =
		    Sailfish_Crypto_Callback_Data_new(
			    NULL,
			    NULL,
			    NULL,
			    (Sailfish_Crypto_CryptoManager_bool_result_callback)callback,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_call(daemon_connection.cryptoProxy,
				  "verify",
				  g_variant_new("(@ay@((ss)iiiiiiiayayayiiaay(a{sv}))(i)(i)s)",
						Sailfish_Crypto_variantFromByteArray(data, dataSize),
						Sailfish_Crypto_variantFromKey(key),
						(int)padding,
						(int)digest,
						cryptosystemProviderName),
				  G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				  Sailfish_Crypto_verifyReady, cbd);
		return 1;
	}
}

int Sailfish_Crypto_CryptoManager_encrypt(
		const unsigned char *data,
		size_t dataSize,
		struct Sailfish_Crypto_Key *key,
		enum Sailfish_Crypto_Key_BlockMode blockMode,
		enum Sailfish_Crypto_Key_EncryptionPadding padding,
		enum Sailfish_Crypto_Key_Digest digest,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_encrypt_callback callback,
		void *callback_context)
{
	if (Sailfish_Crypto_busy() || !Sailfish_Crypto_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Crypto_Callback_Data *cbd =
		    Sailfish_Crypto_Callback_Data_new(
			    NULL,
			    NULL,
			    (Sailfish_Crypto_CryptoManager_data_result_callback)callback,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_call(daemon_connection.cryptoProxy,
				  "encrypt",
				  g_variant_new("(@ay@((ss)iiiiiiiayayayiiaay(a{sv}))(i)(i)(i)s)",
						Sailfish_Crypto_variantFromByteArray(data, dataSize),
						Sailfish_Crypto_variantFromKey(key),
						(int)blockMode,
						(int)padding,
						(int)digest,
						cryptosystemProviderName),
				  G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				  Sailfish_Crypto_encryptReady, cbd);
		return 1;
	}
}

int Sailfish_Crypto_CryptoManager_decrypt(
		const unsigned char *data,
		size_t dataSize,
		struct Sailfish_Crypto_Key *key,
		enum Sailfish_Crypto_Key_BlockMode blockMode,
		enum Sailfish_Crypto_Key_EncryptionPadding padding,
		enum Sailfish_Crypto_Key_Digest digest,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_decrypt_callback callback,
		void *callback_context)
{
	if (Sailfish_Crypto_busy() || !Sailfish_Crypto_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Crypto_Callback_Data *cbd =
		    Sailfish_Crypto_Callback_Data_new(
			    NULL,
			    NULL,
			    (Sailfish_Crypto_CryptoManager_data_result_callback)callback,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_call(daemon_connection.cryptoProxy,
				  "decrypt",
				  g_variant_new("(@ay@((ss)iiiiiiiayayayiiaay(a{sv}))(i)(i)(i)s)",
						Sailfish_Crypto_variantFromByteArray(data, dataSize),
						Sailfish_Crypto_variantFromKey(key),
						(int)blockMode,
						(int)padding,
						(int)digest,
						cryptosystemProviderName),
				  G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				  Sailfish_Crypto_decryptReady, cbd);
		return 1;
	}
}

/****************************** Daemon Connection *******************/

int Sailfish_Crypto_busy()
{
	return daemon_connection.busy;
}

int Sailfish_Crypto_connectedToServer()
{
	return daemon_connection.cryptoProxy != NULL;
}

int Sailfish_Crypto_connectToServer(
		Sailfish_Crypto_connectToServer_callback callback,
		void *callback_context)
{
	if (Sailfish_Crypto_connectedToServer()) {
		return 2;	/* already connected */
	} else if (daemon_connection.busy) {
		return 0;	/* currently connecting */
	} else {
		struct Sailfish_Crypto_Callback_Data *cbd =
		    Sailfish_Crypto_Callback_Data_new(
			   (Sailfish_Crypto_CryptoManager_result_callback)callback,
			    NULL,
			    NULL,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_new_for_bus(
		    G_BUS_TYPE_SESSION,
		    G_DBUS_PROXY_FLAGS_NONE,
		    NULL, /* info */
		    "org.sailfishos.crypto.daemon.discovery",
		    "/Sailfish/Crypto/Discovery",
		    "org.sailfishos.crypto.daemon.discovery",
		    NULL, /* cancellable */
		    Sailfish_Crypto_discoveryProxyReady,
		    cbd);
		return 1;	/* starting to connect */
	}
}

int Sailfish_Crypto_disconnectFromServer(
		Sailfish_Crypto_disconnectFromServer_callback callback,
		void *callback_context)
{
	if (!daemon_connection.p2pBus) {
		return 2;
	} else {
		struct Sailfish_Crypto_Callback_Data *cbd =
		    Sailfish_Crypto_Callback_Data_new(
			    (Sailfish_Crypto_CryptoManager_result_callback)callback,
			    NULL,
			    NULL,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_connection_close(
		    daemon_connection.p2pBus,
		    NULL,
		    Sailfish_Crypto_disconnectReady,
		    cbd);
		return 1;
	}
}
