#include "..\StdAfx.h"
#include "CIEP11Template.h"
#include "../CSP/IAS.h"
#include "../PCSC/CardLocker.h"
#include "../crypto/ASNParser.h"
#include <stdio.h>
#include "../crypto/AES.h"
#include "../PCSC/PCSC.h"

int TokenTransmitCallback(CSlot *data, BYTE *apdu, DWORD apduSize, BYTE *resp, DWORD *respSize) {
	if (apduSize == 2) {
		WORD code = *(WORD*)apdu;
		if (code == 0xfffd) {
			*respSize = sizeof(data->hCard)+2;
			memcpy(resp, &data->hCard, sizeof(data->hCard));
			resp[sizeof(data->hCard)] = 0;
			resp[sizeof(data->hCard) + 1] = 0;

			return SCARD_S_SUCCESS;
		}
		else if (code == 0xfffe) {
			DWORD protocol = 0;
			ODS(String().printf("UNPOWER CARD").lock());
			auto sw = SCardReconnect(data->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, SCARD_UNPOWER_CARD, &protocol);
			if (sw == SCARD_S_SUCCESS)
				SCardBeginTransaction(data->hCard);
			return sw;
		}
		else if (code == 0xffff) {
			DWORD protocol = 0;
			auto sw = SCardReconnect(data->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, SCARD_RESET_CARD, &protocol);
			if (sw == SCARD_S_SUCCESS)
				SCardBeginTransaction(data->hCard);
			ODS(String().printf("RESET CARD").lock());
			return sw;
		}
	}
	ODS(String().printf("APDU: %s\n", dumpHexData(ByteArray(apdu, apduSize), String()).lock()).lock());
	auto sw = SCardTransmit(data->hCard, SCARD_PCI_T1, apdu, apduSize, NULL, resp, respSize);
	if (sw==SCARD_S_SUCCESS)
		ODS(String().printf("RESP: %s\n", dumpHexData(ByteArray(resp, *respSize), String()).lock()).lock());
	else {
		ODS("Errore trasmissione APDU");
	}
	return sw;
}

class CIEData : public CCardTemplateData {
public:
	CK_USER_TYPE userType;
	CAES aesKey;
	CToken token;
	bool init;
	CIEData(CSlot *slot,ByteArray atr) : ias((CToken::TokenTransmitCallback)TokenTransmitCallback,atr), slot(*slot) {
		ByteDynArray key;
		aesKey.Init(key.random(32));
		token.setTransmitCallbackData(slot);
		userType = -1;
		init = false;
	}
	CSlot &slot;
	IAS ias;
	std::shared_ptr<CP11PublicKey> pubKey;
	std::shared_ptr<CP11PrivateKey> privKey;
	std::shared_ptr<CP11Certificate> cert;
	ByteDynArray SessionPIN;

	RESULT InitSession() override;
	RESULT FinalSession() override;
	RESULT Login(CK_USER_TYPE userType, ByteArray &Pin) override;
	RESULT Logout(CK_USER_TYPE userType) override;
	RESULT ReadObjectAttributes(CP11Object *pObject) override;
	RESULT Sign(CP11PrivateKey *pPrivKey, ByteArray &baSignBuffer, ByteDynArray &baSignature, CK_MECHANISM_TYPE mechanism, bool bSilent) override;
	RESULT SignRecover(CP11PrivateKey *pPrivKey, ByteArray &baSignBuffer, ByteDynArray &baSignature, CK_MECHANISM_TYPE mechanism, bool bSilent) override;
	RESULT Decrypt(CP11PrivateKey *pPrivKey, ByteArray &baEncryptedData, ByteDynArray &baData, CK_MECHANISM_TYPE mechanism, bool bSilent) override;
	RESULT GenerateRandom(ByteArray &baRandomData) override;
	RESULT InitPIN(ByteArray &baPin) override;
	RESULT SetPIN(ByteArray &baOldPin, ByteArray &baNewPin, CK_USER_TYPE User) override;
	RESULT GetObjectSize(CP11Object *pObject, CK_ULONG_PTR pulSize) override;
	RESULT SetKeyPIN(CP11Object *pObject, ByteArray &Pin) override;
	RESULT SetAttribute(CP11Object *pObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) override;
	RESULT CreateObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, std::shared_ptr<CP11Object>&pObject) override;
	RESULT DestroyObject(CP11Object &Object) override;
	RESULT GenerateKey(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, std::shared_ptr<CP11Object>&pObject) override;
	RESULT GenerateKeyPair(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, std::shared_ptr<CP11Object>&pPublicKey, std::shared_ptr<CP11Object>&pPrivateKey) override;
};

RESULT CIETemplate::InitLibrary(void *templateData){ return FAIL; }

CIETemplate::~CIETemplate() {}

RESULT CIETemplate::InitCard(std::unique_ptr<CCardTemplateData>&pTemplateData, CSlot &pSlot){ 
	init_func
	ByteArray ATR;
	pSlot.GetATR(ATR);

	pTemplateData.reset(new CIEData(&pSlot, ATR));
	_return(OK)
	exit_func
	_return(FAIL)
}

ByteArray SkipZero(ByteArray &ba) {
	for (DWORD i = 0; i < ba.size(); i++) {
		if (ba[i] != 0)
			return ba.mid(i);
	}
	return ByteArray();
}

BYTE label[] = { 'C','I','E','0' };
RESULT CIEData::InitSession(){ 
	if (!init) {
		ByteDynArray certRaw;
		slot.Connect();
		{
			safeConnection faseConn(slot.hCard);
			CCardLocker lockCard(slot.hCard);
			ias.SetCardContext(&slot);
			ias.ReadPAN();
			ByteDynArray resp;
			ias.ReadDappPubKey(resp);
			ias.InitEncKey();
			ias.GetCertificate(certRaw, true);
		}

		CK_BBOOL vtrue = TRUE;
		CK_BBOOL vfalse = FALSE;

		PCCERT_CONTEXT certDS = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, certRaw.lock(), certRaw.size());
		if (certDS != nullptr) {
			pubKey = std::make_shared<CP11PublicKey>(this);
			privKey = std::make_shared<CP11PrivateKey>(this);
			cert = std::make_shared<CP11Certificate>(this);

			CASNParser keyParser;
			keyParser.Parse(ByteArray(certDS->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, certDS->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData));
			auto Module = SkipZero(keyParser.tags[0]->tags[0]->content);
			auto Exponent = SkipZero(keyParser.tags[0]->tags[1]->content);
			CK_LONG keySizeBits = Module.size() * 8;
			pubKey->addAttribute(CKA_LABEL, VarToByteArray(label));
			pubKey->addAttribute(CKA_ID, VarToByteArray(label));
			pubKey->addAttribute(CKA_PRIVATE, VarToByteArray(vfalse));
			pubKey->addAttribute(CKA_TOKEN, VarToByteArray(vtrue));
			pubKey->addAttribute(CKA_MODULUS, Module);
			pubKey->addAttribute(CKA_PUBLIC_EXPONENT, Exponent);
			pubKey->addAttribute(CKA_MODULUS_BITS, VarToByteArray(keySizeBits));
			pubKey->addAttribute(CKA_VERIFY, VarToByteArray(vtrue));
			CK_KEY_TYPE keyrsa = CKK_RSA;
			pubKey->addAttribute(CKA_KEY_TYPE, VarToByteArray(keyrsa));
			slot.AddP11Object(pubKey);

			privKey->addAttribute(CKA_LABEL, VarToByteArray(label));
			privKey->addAttribute(CKA_ID, VarToByteArray(label));
			privKey->addAttribute(CKA_PRIVATE, VarToByteArray(vtrue));
			privKey->addAttribute(CKA_TOKEN, VarToByteArray(vtrue));
			privKey->addAttribute(CKA_KEY_TYPE, VarToByteArray(keyrsa));
			privKey->addAttribute(CKA_MODULUS, Module);
			privKey->addAttribute(CKA_PUBLIC_EXPONENT, Exponent);
			privKey->addAttribute(CKA_SIGN, VarToByteArray(vtrue));
			slot.AddP11Object(privKey);

			cert->addAttribute(CKA_LABEL, VarToByteArray(label));
			cert->addAttribute(CKA_ID, VarToByteArray(label));
			cert->addAttribute(CKA_PRIVATE, VarToByteArray(vfalse));
			cert->addAttribute(CKA_TOKEN, VarToByteArray(vtrue));
			cert->addAttribute(CKA_VALUE, ByteArray(certDS->pbCertEncoded, certDS->cbCertEncoded));
			cert->addAttribute(CKA_ISSUER, ByteArray(certDS->pCertInfo->Issuer.pbData, certDS->pCertInfo->Issuer.cbData));
			cert->addAttribute(CKA_SERIAL_NUMBER, ByteArray(certDS->pCertInfo->SerialNumber.pbData, certDS->pCertInfo->SerialNumber.cbData));
			cert->addAttribute(CKA_SUBJECT, ByteArray(certDS->pCertInfo->Subject.pbData, certDS->pCertInfo->Subject.cbData));
			CK_CERTIFICATE_TYPE certx509 = CKC_X_509;
			cert->addAttribute(CKA_CERTIFICATE_TYPE, VarToByteArray(certx509));
			CK_DATE start, end;
			SYSTEMTIME sFrom, sTo;
			String temp;
			if (!FileTimeToSystemTime(&certDS->pCertInfo->NotBefore, &sFrom))
				return FAIL;
			if (!FileTimeToSystemTime(&certDS->pCertInfo->NotAfter, &sTo))
				return FAIL;
			temp.printf("%04i", sFrom.wYear); VarToByteArray(start.year).copy(temp.toByteArray());
			temp.printf("%02i", sFrom.wMonth); VarToByteArray(start.month).copy(temp.toByteArray());
			temp.printf("%02i", sFrom.wDay); VarToByteArray(start.day).copy(temp.toByteArray());
			temp.printf("%04i", sTo.wYear); VarToByteArray(end.year).copy(temp.toByteArray());
			temp.printf("%02i", sTo.wMonth); VarToByteArray(end.month).copy(temp.toByteArray());
			temp.printf("%02i", sTo.wDay); VarToByteArray(end.day).copy(temp.toByteArray());
			cert->addAttribute(CKA_START_DATE, VarToByteArray(start));
			cert->addAttribute(CKA_END_DATE, VarToByteArray(end));

			slot.AddP11Object(cert);
		}
		init = true;
	}
	return OK;
}
RESULT CIEData::FinalSession(){ 
	return OK; 
}

RESULT CIETemplate::MatchCard(bool &bMatched, CSlot &pSlot){ 
	init_func
	CToken token;

	pSlot.Connect();
	{
		safeConnection faseConn(pSlot.hCard);
		ByteArray ATR;
		pSlot.GetATR(ATR);
		token.setTransmitCallback((CToken::TokenTransmitCallback)TokenTransmitCallback, &pSlot);
		IAS ias((CToken::TokenTransmitCallback)TokenTransmitCallback, ATR);
		ias.SetCardContext(&pSlot);
		{
			safeTransaction trans(faseConn,SCARD_LEAVE_CARD);
			ias.ReadPAN();
		}
		bMatched = true;
		_return(OK);
	}
	exit_func
	_return(FAIL)
}

RESULT CIETemplate::GetSerial(CSlot &pSlot, ByteDynArray &baSerial){
	init_func
		CToken token;

	pSlot.Connect();
	{
		safeConnection faseConn(pSlot.hCard);
		CCardLocker lockCard(pSlot.hCard);
		ByteArray ATR;
		pSlot.GetATR(ATR);
		IAS ias((CToken::TokenTransmitCallback)TokenTransmitCallback, ATR);
		ias.SetCardContext(&pSlot);
		ias.ReadPAN();
		String numSerial;
		dumpHexData(ias.PAN.mid(5, 6), numSerial, false);
		baSerial = ByteArray((BYTE*)numSerial.lock(),numSerial.strlen());
		_return(OK);
	}
	exit_func
		_return(FAIL)
}
RESULT CIETemplate::GetModel(CSlot &pSlot, String &szModel){ 
	szModel = ""; 
	return OK;
}
RESULT CIETemplate::GetTokenFlags(CSlot &pSlot, DWORD &dwFlags){ 
	dwFlags = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | CKF_REMOVABLE_DEVICE;
	return OK;
}

RESULT CIEData::Login(CK_USER_TYPE userType, ByteArray &Pin) {
	init_func
	CToken token;

	SessionPIN.clear();
	userType = -1;

	slot.Connect();
	ias.SetCardContext(&slot);
	ias.token.Reset();
	{
		safeConnection safeConn(slot.hCard);
		CCardLocker lockCard(slot.hCard);

		ias.SelectAID_IAS();
		ias.InitDHParam();

		if (ias.DappPubKey.isEmpty()) {
			ByteDynArray DappKey;
			ias.ReadDappPubKey(DappKey);
		}

		ias.InitExtAuthKeyParam();
		// faccio lo scambio di chiavi DH	
		if (ias.Callback != nullptr)
			ias.Callback(1, "DiffieHellman", ias.CallbackData);
		ias.DHKeyExchange();
		// DAPP
		if (ias.Callback != nullptr)
			ias.Callback(2, "DAPP", ias.CallbackData);
		ias.DAPP();
		// verifica PIN
		DWORD sw;
		if (ias.Callback != nullptr)
			ias.Callback(3, "Verify PIN", ias.CallbackData);
		if (userType == CKU_USER) {
			ByteDynArray FullPIN;
			ias.GetFirstPIN(FullPIN);
			FullPIN.append(Pin);
			sw = ias.VerifyPIN(FullPIN);
		}
		else if (userType == CKU_SO) {
			sw = ias.VerifyPUK(Pin);
		}
		else
			return CKR_ARGUMENTS_BAD;

		if (sw == 0x6983) {
			if (userType == CKU_USER)
				ias.IconaSbloccoPIN();
			return CKR_PIN_LOCKED;
		}
		if (sw >= 0x63C0 && sw <= 0x63CF) {
			//*pcAttemptsRemaining = sw - 0x63C0;
			return CKR_PIN_INCORRECT;
		}
		if (sw == 0x6700) {
			return CKR_PIN_INCORRECT;
		}
		if (sw == 0x6300)
			return CKR_PIN_INCORRECT;
		if (sw != 0x9000) {
			throw CSCardException((WORD)sw);
		}

		aesKey.Encode(Pin, SessionPIN);
		userType = userType;
		_return(OK);
	}
	exit_func
		_return(FAIL)
}
RESULT CIEData::Logout(CK_USER_TYPE userType){ 
	userType = -1;
	SessionPIN.clear();
	return OK; 
}
RESULT CIEData::ReadObjectAttributes(CP11Object *pObject){ 
	return OK; 
}
RESULT CIEData::Sign(CP11PrivateKey *pPrivKey, ByteArray &baSignBuffer, ByteDynArray &baSignature, CK_MECHANISM_TYPE mechanism, bool bSilent){ 
	init_func
	CToken token;
	if (userType == CKU_USER) {
		ByteDynArray Pin;
		slot.Connect();
		ias.SetCardContext(&slot);
		ias.token.Reset();
		{
			safeConnection safeConn(slot.hCard);
			CCardLocker lockCard(slot.hCard);
			aesKey.Decode(SessionPIN, Pin);
			ias.SelectAID_IAS();
			ias.SelectAID_CIE();
			ias.DHKeyExchange();
			ias.DAPP();

			ByteDynArray FullPIN;
			ias.GetFirstPIN(FullPIN);
			FullPIN.append(Pin);
			CARD_R_CALL(ias.VerifyPIN(FullPIN));
			ias.Sign(baSignBuffer, baSignature);
		}
	}
	_return(OK);
	exit_func
	_return(FAIL)
}

RESULT CIEData::InitPIN(ByteArray &baPin){ 
	init_func
	CToken token;
	if (userType == CKU_SO) {
		// posso usarla solo se sono loggato come so
		ByteDynArray Pin;
		slot.Connect();
		ias.SetCardContext(&slot);
		ias.token.Reset();
		{
			safeConnection safeConn(slot.hCard);
			CCardLocker lockCard(slot.hCard);
			aesKey.Decode(SessionPIN, Pin);
			ias.SelectAID_IAS();
			ias.SelectAID_CIE();

			ias.DHKeyExchange();
			ias.DAPP();
			CARD_R_CALL(ias.VerifyPUK(Pin))
			CARD_R_CALL(ias.UnblockPIN())

			ByteDynArray changePIN;
			ias.GetFirstPIN(changePIN);
			changePIN.append(baPin);

			CARD_R_CALL(ias.ChangePIN(changePIN))
		}
	}
	else
		return CKR_FUNCTION_NOT_SUPPORTED;
	_return(OK);
	exit_func
		_return(FAIL)
}

RESULT CIEData::SetPIN(ByteArray &baOldPin, ByteArray &baNewPin, CK_USER_TYPE User)
{
	init_func
	CToken token;
	if (userType != CKU_SO) {
		// posso usarla sia se sono loggato come user sia se non sono loggato
		ByteDynArray Pin;
		slot.Connect();
		ias.SetCardContext(&slot);
		ias.token.Reset();
		{
			safeConnection safeConn(slot.hCard);
			CCardLocker lockCard(slot.hCard);
			ias.SelectAID_IAS();
			if (userType != CKU_USER)
				ias.InitDHParam();
			ias.SelectAID_CIE();

			if (userType != CKU_USER) {
				ias.ReadPAN();
				ByteDynArray resp;
				ias.ReadDappPubKey(resp);
			}

			ias.DHKeyExchange();
			ias.DAPP();
			ByteDynArray oldPIN,newPIN;
			ias.GetFirstPIN(oldPIN);
			newPIN = oldPIN;
			oldPIN.append(baOldPin);
			newPIN.append(baNewPin);

			CARD_R_CALL(ias.VerifyPIN(oldPIN))
			CARD_R_CALL(ias.ChangePIN(oldPIN,newPIN))
		}
	}
	else
		return CKR_FUNCTION_NOT_SUPPORTED;
	_return(OK);
	exit_func
	_return(FAIL)
}

RESULT CIEData::SignRecover(CP11PrivateKey *pPrivKey, ByteArray &baSignBuffer, ByteDynArray &baSignature, CK_MECHANISM_TYPE mechanism, bool bSilent){ return FAIL; }
RESULT CIEData::Decrypt(CP11PrivateKey *pPrivKey, ByteArray &baEncryptedData, ByteDynArray &baData, CK_MECHANISM_TYPE mechanism, bool bSilent){ return FAIL; }
RESULT CIEData::GenerateRandom(ByteArray &baRandomData){ return FAIL; }
RESULT CIEData::GetObjectSize(CP11Object *pObject, CK_ULONG_PTR pulSize){ return FAIL; }
RESULT CIEData::SetKeyPIN(CP11Object *pObject, ByteArray &Pin){ return FAIL; }
RESULT CIEData::SetAttribute(CP11Object *pObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount){ return FAIL; }
RESULT CIEData::CreateObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, std::shared_ptr<CP11Object>&pObject){ return FAIL; }
RESULT CIEData::DestroyObject(CP11Object &Object){ return FAIL; }
RESULT CIEData::GenerateKey(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, std::shared_ptr<CP11Object>&pObject){ return FAIL; }
RESULT CIEData::GenerateKeyPair(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, std::shared_ptr<CP11Object>&pPublicKey, std::shared_ptr<CP11Object>&pPrivateKey){ return FAIL; }
