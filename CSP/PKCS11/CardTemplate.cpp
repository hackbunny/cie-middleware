#include "../StdAfx.h"
#include "cardtemplate.h"
#include "../util/util.h"
#include "../util/moduleinfo.h"
#include "CIEP11Template.h"

static char *szCompiledFile=__FILE__;

const char szTemplatesQry[]="./TEMPLATES";
const char szTemplateNode[]="TEMPLATE";
const char szLibPathQry[]="./DLLMANAGER";
const char szNameQry[]="./NAME";

extern CModuleInfo moduleInfo;

namespace p11 {

static const char *szTemplateFuncListName = "TemplateGetFunctionList";
TemplateVector CCardTemplate::g_mCardTemplates;

CCardTemplateData::~CCardTemplateData(void) {}

CCardTemplate::CCardTemplate(void)
{
	hLibrary=NULL;
}

CCardTemplate::~CCardTemplate(void)
{
	if (hLibrary)
		FreeLibrary(hLibrary);
}

RESULT CCardTemplate::AddTemplate(std::shared_ptr<CCardTemplate> pTemplate) {
	init_func
	g_mCardTemplates.emplace_back(std::move(pTemplate));
	_return(OK)
	exit_func
	_return(FAIL)
}

RESULT CCardTemplate::DeleteTemplateList() {
	init_func
	g_mCardTemplates.clear();
	_return(OK)
	exit_func
	_return(FAIL)
}

RESULT CCardTemplate::InitTemplateList()
{
	init_func

		auto pTemplate = std::unique_ptr<CIETemplate>(new CIETemplate());
	pTemplate->szName = "CIE";// "Carta d'Identità Elettronica";
	pTemplate->szManifacturer = "";

	if (AddTemplate(std::move(pTemplate))) {
		throw CStringException(ERR_CANT_ADD_SLOT);
	}

	_return(OK)
		exit_func
		_return(FAIL)
}

RESULT CCardTemplate::GetTemplate(CSlot &pSlot,std::shared_ptr<CCardTemplate>&pTemplate)
{
	init_func
	for (DWORD i=0;i<g_mCardTemplates.size();i++) {
		bool bMatched;
		if (g_mCardTemplates[i]->MatchCard(bMatched,pSlot)) {
			continue;
		}
		if (bMatched) {
			pTemplate=g_mCardTemplates[i];
			_return(OK)
		}
	}
	pTemplate=nullptr;
	_return(OK)
	exit_func
	_return(FAIL)
}

//RESULT CCardTemplate::InitLibrary(const char *szPath,void *templateData)
//{
//	init_func
//	hLibrary=LoadLibrary(szPath);
//	if (hLibrary==NULL) {
//		throw CStringException(CWinException(), ERR_CANT_LOAD_LIBRARY);
//	}
//
//	templateFuncListFunc funcList;
//	funcList=(templateFuncListFunc)GetProcAddress(hLibrary,szTemplateFuncListName);
//	if (!funcList) {
//		throw CStringException(ERR_GET_LIBRARY_FUNCTION_LIST);
//	}
//	
//	if (funcList(&FunctionList)) {
//		throw CStringException(ERR_CALL_LIBRARY_FUNCTION_LIST);
//	}
//	
//	if (FunctionList.templateInitLibrary(*this,templateData)) {
//		throw CStringException(ERR_INIT_LIBRARY);
//	}
//
//	_return(OK)
//	exit_func
//	_return(FAIL)
//}

};