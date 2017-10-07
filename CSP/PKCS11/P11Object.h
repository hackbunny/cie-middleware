#pragma once

#include "session.h"
#include <map>

#pragma pack(1)
#include "pkcs11.h"
#pragma pack()

namespace p11 {

typedef std::map <CK_ATTRIBUTE_TYPE,ByteDynArray> AttributeMap;

class CSession;

class CP11Object
{
public:
	RESULT bReadValue;
	static DWORD dwP11ObjectCnt;

	CSlot *pSlot;
	CCardTemplateData *pTemplateData; //dati specifici per il template della carta

	CP11Object(CK_OBJECT_CLASS objClass, CCardTemplateData *TemplateData);
	CK_OBJECT_CLASS ObjClass;
	AttributeMap attributes;
	RESULT addAttribute(CK_ATTRIBUTE_TYPE type,ByteArray &data);
	RESULT addAttribute(CK_ATTRIBUTE_TYPE type,BYTE *pData,DWORD dwLen);
	virtual RESULT getAttribute(CK_ATTRIBUTE_TYPE type,ByteArray *&pValue);

	virtual CK_RV GetAttributeValue(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
	virtual RESULT SetAttributes(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
	virtual RESULT GetObjectSize(CK_ULONG_PTR pulSize);

	RESULT IsPrivate(bool &bPrivate);
};

class CP11Certificate : public CP11Object
{
public:
	CP11Certificate(CCardTemplateData *TemplateData);
	RESULT getAttribute(CK_ATTRIBUTE_TYPE type,ByteArray *&pValue);
	RESULT SetAttributes(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
};

class CP11Data : public CP11Object
{
public:
	CP11Data(CCardTemplateData *TemplateData);
	RESULT getAttribute(CK_ATTRIBUTE_TYPE type,ByteArray *&pValue);
	RESULT SetAttributes(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
};

class CP11PublicKey : public CP11Object
{
public:
	CP11PublicKey(CCardTemplateData *TemplateData);
	RESULT getAttribute(CK_ATTRIBUTE_TYPE type,ByteArray *&pValue);
};

class CP11PrivateKey : public CP11Object
{
public:
	CP11PrivateKey(CCardTemplateData *TemplateData);
	RESULT getAttribute(CK_ATTRIBUTE_TYPE type,ByteArray *&pValue);
};

}