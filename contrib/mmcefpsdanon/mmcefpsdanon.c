/* mmcefpsdanon.c
 * custom module: Pseudo anonymize selected fields inside an CEF message using HMAC SHA 256
 *
 * Copyright 2023, EQUANS
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"

// Define bool
typedef uint bool
#define TRUE (1==1)
#define FALSE !TRUE

// Modes
#define SIMPLE_MODE 0	 /* just overwrite */
#define REWRITE_MODE 1	 /* rewrite IP address, canoninized */


MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmcefpsdanon")

DEF_OMOD_STATIC_DATA

// 000 - Set instance/workInstance variables

typedef struct _instanceData {
	uchar *key;
	int16_t keylen;		/* cached length of key, to avoid recomputation */
	const EVP_MD *algo;
	uchar *jsonRoot;	/**< container where to store fields */
	int nHashedFields;
    uchar **hashedFields;
} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
} wrkrInstanceData_t;

static inline void
setInstParamDefaults(instanceData *pData)
{
	pData->key = NULL;
	pData->jsonRoot = NULL;
	pData->nHashedFields = 0;
	pData->hashedFields = NULL;
}

// 00 - Set configuration variables

struct modConfData_s {
	rsconf_t *pConf;	/* our overall config object */
};

static modConfData_t *loadModConf = NULL;	/* modConf ptr to use for the current load process */
static modConfData_t *runModConf = NULL;	/* modConf ptr to use for the current exec process */


// 0 - Set module input parameters (Tables for interfacing with the v6 config system action (instance) parameters)

static struct cnfparamdescr actpdescr[] = 
    {
        { "key", eCmdHdlrString, 1 },
        { "hashfunction", eCmdHdlrString, 1 },
        { "hashedfields", eCmdHdlrArray, 1}
    }; 

static struct cnfparamblk actpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(actpdescr)/sizeof(struct cnfparamdescr),
	  actpdescr
	};


// 1 - Load configurations

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
	loadModConf = pModConf;
	pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
CODESTARTcheckCnf
ENDcheckCnf

BEGINactivateCnf
CODESTARTactivateCnf
	runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
ENDfreeCnf

// 2 - Load instance and work instance

BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance

BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature

BEGINfreeInstance
CODESTARTfreeInstance
	free(pData->key);
    free(pData->jsonRoot);
	for(i = 0 ; i < pData->nHashedFields ; ++i) {
		free((void*) pData->hashedFields[i]);
	}
	free(pData->hashedFields);
	pData->nHashedFields = 0;
ENDfreeInstance

BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
ENDfreeWrkrInstance

// 3 - Extract/Load module input parameters

BEGINnewActInst
	struct cnfparamvals *pvals;
	char *ciphername;
	int i;
CODESTARTnewActInst
	DBGPRINTF("newActInst (mmcefpsdanon)\n");
	if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	CODE_STD_STRING_REQUESTnewActInst(1)
	CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
	CHKiRet(createInstance(&pData));
	setInstParamDefaults(pData);

	for(i = 0 ; i < actpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(actpblk.descr[i].name, "key")) {
			pData->key = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
			pData->keylen = es_strlen(pvals[i].val.d.estr);
		} 
		else if(!strcmp(actpblk.descr[i].name, "hashfunction")) {
			ciphername = es_str2cstr(pvals[i].val.d.estr, NULL);
			pData->algo = EVP_get_digestbyname(ciphername);
			if(pData->algo == NULL) {
				LogError(0, RS_RET_CRY_INVLD_ALGO,
					"hashFunction '%s' unknown to openssl - "
					"cannot continue", ciphername);
				free(ciphername);
				ABORT_FINALIZE(RS_RET_CRY_INVLD_ALGO);
			}
			free(ciphername);
        } 
		else if(!strcmp(actpblk.descr[i].name, "hashedfields")) {
			pData->nHashedFields = pvals[i].val.d.ar->nmemb;
			CHKmalloc(pData->hashedFields = malloc(sizeof(uchar *) *  pData->nHashedFields ));
			for(int j = 0 ; j <  pData->nHashedFields ; ++j) {
				char *cstr = es_str2cstr(pvals[i].val.d.ar->arr[j], NULL);
				pData->hashedfields[j] = (uchar *)cstr;
			}
		} 
		else {
			dbgprintf("mmcefpsdanon: program error, parameter non-handled "
			  "param '%s'\n", actpblk.descr[i].name);
		}
	}
	if(pData->jsonRoot == NULL) {
		CHKmalloc(pData->jsonRoot = (uchar*) strdup("!"));
	}
CODE_STD_FINALIZERnewActInst
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINdbgPrintInstInfo
	int i;
CODESTARTdbgPrintInstInfo
	dbgprintf("mmcefpsdanon\n");
	dbgprintf("\thashedfields=[");
	for(i = 0 ; i < pData->nHashedFields ; ++i)
		dbgprintf("\t%s\n", pData->hashedfields[i]);
	dbgprintf("\t]\n");
ENDdbgPrintInstInfo

BEGINtryResume
CODESTARTtryResume
ENDtryResume

//Hashing functions using HMAC from openSSL

/* Turn the binary data in bin of length len into a printable hex string.*/
/* Note: "print" must be 2*len+1 (for \0). */
static void
b2a_hex(uchar *bin, int len, uchar *print)
{
	static const char hexchars[16] =
	   {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	int iSrc, iDst;

	for(iSrc = iDst = 0 ; iSrc < len ; ++iSrc) {
		print[iDst++] = hexchars[bin[iSrc]>>4];
		print[iDst++] = hexchars[bin[iSrc]&0x0f];
	}
	print[iDst] = '\0';
}

static rsRetVal
hashfield(instanceData *pData, uchar* pField, int pLenField )
{
	unsigned int hashlen;
	uchar hash[EVP_MAX_MD_SIZE];
	uchar hashPrintable[2*EVP_MAX_MD_SIZE+1];
	DEFiRet;

	HMAC(pData->algo, pData->key, pData->keylen,
	     pField, pLenField, hash, &hashlen);

	b2a_hex(hash, hashlen, hashPrintable);
	strcpy(pField, hashPrintable);
	RETiRet;
}

// Functions to extract th data

static rsRetVal
extractHeader(uchar *msgText, int msgLen, int *currIdx, uchar *fieldValue)
{
    int i, j;
    int lstV = *currIdx;
    int lstS = *currIdx;
    uchar *unitC =  msgText;
    DEFiRet;

	// Detect the last column or first space after the CEF parameters
    i = *currIdx;
	while(i < msgLen && *unitC != '='){
        if( *unitC == ' ' ) lstS = i;
        else if( *unitC == '|' ) lstV = i;
        unitC = unitC + 1;
        i++;
	}
	if(lstS > lstV){
		strncpy(fieldValue, msgText, lstS);
		*currIdx = lstS + 1;
	} else {
		strncpy(fieldValue, msgText, lstV);
		*currIdx = lstV + 1;
	}
    RETiRet;
}

static rsRetVal
extractField(uchar *msgText, int msgLen, int *currIdx, uchar *fieldName, uchar *fieldValue)
{
    int i, j;
    int detE = 0;
    int lstE = *currIdx;
    int lstS = *currIdx;
    uchar *unitC =  msgText[*currIdx];
    DEFiRet;

	// Identify separator "=" and last empty space before following separator "="
    i = *currIdx;
    while(i < msgLen){
        if(*unitC == '='){
            if(!detE){
                lstE = i;
                detE++;
            } else break;
        } else if(detE && *unitC == ' '){
            lstS = i;
        }
        unitC = unitC + 1;
        i++;
    }
	if(!detE) return;
	if(lstS < lstE) lstS = msgLen;

    // Copy the values name:value
    int lenE = lstE - *currIdx;
	int lenS = lstS - lstE;
    strncpy(fieldName, msgText + *currIdx, lenE);
	fieldName[lenE] = '\0';
    strncpy(fieldValue, msgText + lstE + 1, lenS - 1);
	fieldValue[lenS - 1] = '\0';

    *currIdx = lstS + 1;
    RETiRet;
}

static rsRetVal
parse_fields(instanceData *pData, smsg_t *pMsg, uchar *msgtext, int lenMsg)
{
	uchar fieldValue[1024];
	uchar fieldName[256];
	struct json_object *jsonRoot;
	struct json_object *jsonValue;
	int field;
	int currIdx = 0;
	DEFiRet;

	// Initialize json container
	jsonRoot =  json_object_new_object();
	if(jsonRoot == NULL) {
		ABORT_FINALIZE(RS_RET_ERR);
	}

	// Extract header
	CHKiRet(extractHeader(msgtext, lenMsg, &currIdx, (uchar*) fieldValue));
	DBGPRINTF("mmcefpsdanon:header:%s\n", fieldValue);
	jsonValue = json_object_new_string((char*)fieldValue);
	json_object_object_add(jsonRoot, (char*)fieldName, jsonValue);

    //Extract body fields
	while(currIdx < lenMsg) {
		CHKiRet(extractField(msgtext, lenMsg, &currIdx, (uchar*) fieldName, (uchar*) fieldValue));
		DBGPRINTF("mmcefpsdanon:field:%d:%s\n", fieldName, fieldValue);

		// Hash field if necessary
		for(int i=0; i<pData->nHashedFields; ++i){
			if(!strcmp(pData->hashedFields[i], fieldName)){
				CHKiRet(hashfield(pData, fieldValue));
			}
		}

		jsonValue = json_object_new_string((char*)fieldValue);
		json_object_object_add(jsonRoot, (char*)fieldName, jsonValue);
	}
	msgAddJSON(pMsg, pData->jsonRoot, jsonRoot, 0, 0);
	RETiRet;
}

BEGINdoAction
	instanceData *pData = pWrkrData->pData;
	smsg_t **ppMsg = (smsg_t **) pMsgData;
	smsg_t *pMsg = ppMsg[0];
	uchar *msg;
	int lenMsg;
CODESTARTdoAction
	lenMsg = getMSGLen(pMsg);
	msg = getMSG(pMsg);
	iRet = parse_fields(pWrkrData->pData, pMsg, msg, lenMsg);
ENDdoAction

// 4 - Follow-up actions

NO_LEGACY_CONF_parseSelectorAct

BEGINmodExit
CODESTARTmodExit
	EVP_cleanup();
ENDmodExit

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION;
CODEmodInit_QueryRegCFSLineHdlr
	DBGPRINTF("mmcefpsdanon: module compiled with rsyslog version %s.\n", VERSION);
	OpenSSL_add_all_digests();
ENDmodInit
