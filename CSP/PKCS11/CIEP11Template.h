#pragma once
#include "CardTemplate.h"
#include "Slot.h"
#include <memory>

using namespace p11;

class CIETemplate : public CCardTemplate {
public:
	~CIETemplate() override;
	RESULT InitLibrary(void *templateData) override;
	RESULT InitCard(std::unique_ptr<CCardTemplateData>&pTemplateData, CSlot &pSlot) override;
	RESULT MatchCard(bool &bMatched, CSlot &pSlot) override;
	RESULT GetSerial(CSlot &pSlot, ByteDynArray &baSerial) override;
	RESULT GetModel(CSlot &pSlot, String &szModel) override;
	RESULT GetTokenFlags(CSlot &pSlot, DWORD &dwFlags) override;
};
