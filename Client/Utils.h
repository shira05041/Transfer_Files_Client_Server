#pragma once

#include "RSAWrapper.h"
#include "AESWrapper.h"
#include <iostream>
#include <array>

#define CHUNK_SIZE  (1024)
#define DEFAULT_CLIENT_ID (64f3f63985f04beb81a0e43321880182)
#define UUID_SIZE (16)
#define MAX_USERNAME (255)
#define MAX_FILENAME (255)
#define PUB_KEY_SIZE (RSAPublicWrapper::KEYSIZE)		 // RSA 1024 bit X509 format
#define CONTENT_SIZE (4)
#define HEADER_SIZE (23)
#define HEADER_SIZE_RESPONSE (7)
#define BLOCK_SIZE (16)  // AES block size
#define PUB_KEY_SIZE (160) //(RSAPublicWrapper::KEYSIZE)		 // RSA 1024 bit X509 format
#define SYMMETRIC_KEY_SIZE (AESWrapper::DEFAULT_KEYLENGTH)  // AES-CBC 128 bit
#define CRC_SIZE (4)
#define TRANSFER_INFO ("transfer.info.txt")
#define ME_INFO ("me.info.txt")
#define SEND_TIMES (3)

/* definition of the codes of the various requests */
#define REGISTER_CODE (1100)
#define REGISTER_SUCCESS (2100)
#define REGISTER_FAILED (2101)
#define PUBLIC_CODE (1101)
#define RECIVE_AES_KEY (2102)  //server recived public key and sent AES key encrypred by pub_key
#define SEND_FILE_CODE (1103)
#define RECIVE_CRC_CODE (2103) //server recived the file and sent the CRC
#define CRC_SUCCSES (1104)
#define CRC_FAILED (1105)
#define CRC_FAILED_FOUR_TIMES (1106)
#define RECIVED_MSG_THANK_YOU (2104)


struct ResponseHeader {
	uint8_t  serverVersion = 0;
	uint16_t statusCode = 0;
	uint32_t payloadSize = 0;
};