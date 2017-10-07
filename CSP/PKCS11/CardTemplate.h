#pragma once

#include "../PCSC/token.h"
#include "session.h"
#include <memory>


namespace p11 {

typedef std::vector<std::shared_ptr<CCardTemplate>> TemplateVector;

class CCardTemplateData
{
public:
	virtual ~CCardTemplateData(void);

	virtual RESULT InitSession() = 0;
	virtual RESULT FinalSession() = 0;
	virtual RESULT Login(CK_USER_TYPE userType, ByteArray &Pin) = 0;
	virtual RESULT Logout(CK_USER_TYPE userType) = 0;
	virtual RESULT ReadObjectAttributes(CP11Object *pObject) = 0;
	virtual RESULT Sign(CP11PrivateKey *pPrivKey, ByteArray &baSignBuffer, ByteDynArray &baSignature, CK_MECHANISM_TYPE mechanism, bool bSilent) = 0;
	virtual RESULT SignRecover(CP11PrivateKey *pPrivKey, ByteArray &baSignBuffer, ByteDynArray &baSignature, CK_MECHANISM_TYPE mechanism, bool bSilent) = 0;
	virtual RESULT Decrypt(CP11PrivateKey *pPrivKey, ByteArray &baEncryptedData, ByteDynArray &baData, CK_MECHANISM_TYPE mechanism, bool bSilent) = 0;
	virtual RESULT GenerateRandom(ByteArray &baRandomData) = 0;
	virtual RESULT InitPIN(ByteArray &baPin) = 0;
	virtual RESULT SetPIN(ByteArray &baOldPin, ByteArray &baNewPin, CK_USER_TYPE User) = 0;
	virtual RESULT GetObjectSize(CP11Object *pObject, CK_ULONG_PTR pulSize) = 0;
	virtual RESULT SetKeyPIN(CP11Object *pObject, ByteArray &Pin) = 0;
	virtual RESULT SetAttribute(CP11Object *pObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) = 0;
	virtual RESULT CreateObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, std::shared_ptr<CP11Object>&pObject) = 0;
	virtual RESULT DestroyObject(CP11Object &Object) = 0;
	virtual RESULT GenerateKey(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, std::shared_ptr<CP11Object>&pObject) = 0;
	virtual RESULT GenerateKeyPair(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, std::shared_ptr<CP11Object>&pPublicKey, std::shared_ptr<CP11Object>&pPrivateKey) = 0;
};

class CCardTemplate
{
public:
	CCardTemplate(void);
	virtual ~CCardTemplate(void);

	static TemplateVector g_mCardTemplates;

	static RESULT AddTemplate(std::shared_ptr<CCardTemplate> pTemplate);

	static RESULT InitTemplateList();
	static RESULT DeleteTemplateList();

	static RESULT GetTemplate(CSlot &pSlot,std::shared_ptr<CCardTemplate>&pTemplate);

	RESULT InitLibrary(const char *szPath,void *templateData);

	HMODULE hLibrary;
	virtual RESULT InitLibrary(void *templateData) = 0;
	virtual RESULT InitCard(std::unique_ptr<CCardTemplateData>&pTemplateData, CSlot &pSlot) = 0;
	virtual RESULT MatchCard(bool &bMatched, CSlot &pSlot) = 0;
	virtual RESULT GetSerial(CSlot &pSlot, ByteDynArray &baSerial) = 0;
	virtual RESULT GetModel(CSlot &pSlot, String &szModel) = 0;
	virtual RESULT GetTokenFlags(CSlot &pSlot, DWORD &dwFlags) = 0;

	String szName;
	String szManifacturer;
};

};