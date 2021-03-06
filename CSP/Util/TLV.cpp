#include "../StdAfx.h"
#include "tlv.h"

static char *szCompiledFile=__FILE__;

CTLV::CTLV(ByteArray &data)
{
	init_func
	uint32_t dwPtr=0;
	while (dwPtr<data.size()) {
		BYTE btLen=data[dwPtr+1];
		if (btLen<255) {
			if (dwPtr+btLen+2>data.size()) _returnVoid
			map[data[dwPtr]]=ByteArray(data.mid(dwPtr,btLen+2));
			dwPtr+=btLen+2;
		}
		else {
			uint32_t dwLen = ByteArrayToVar(data.mid(dwPtr + 2),uint32_t);
			if (dwPtr + dwLen + 2 + sizeof(uint32_t)>data.size()) _returnVoid
			map[data[dwPtr]] = ByteArray(data.mid(dwPtr, dwLen + 2 + sizeof(uint32_t)));
			dwPtr += dwLen + 2 + sizeof(uint32_t);
		}
	}
	exit_func
}

CTLV::~CTLV(void)
{
}

RESULT CTLV::getTAG(BYTE Tag,ByteArray *&Value)
{
	init_func
	tlvMap::iterator it=map.find(Tag);
	if (it!=map.end())
		Value=&it->second;
	else
		Value=NULL;
	_return(OK)
	exit_func
	_return(FAIL)
}

RESULT CTLV::getValue(BYTE Tag,ByteArray &Value)
{
	init_func
	tlvMap::iterator it=map.find(Tag);
	if (it!=map.end()) {
		if (it->second[0]<0x255)
			Value=it->second.mid(2);
		else
			Value=it->second.mid(6);
	}
	else 
		_return(OK)
	_return(OK)
	exit_func
	_return(FAIL)
}

CTLVCreate::CTLVCreate()
{
}

CTLVCreate::~CTLVCreate(void)
{
}

RESULT CTLVCreate::getValue(BYTE Tag,ByteDynArray *&Value)
{
	init_func
	tlvCreateMap::iterator it=map.find(Tag);
	if (it!=map.end())
		Value=&it->second;
	else
		Value=NULL;
	_return(OK)
	exit_func
	_return(FAIL)
}

RESULT CTLVCreate::addValue(BYTE Tag,ByteDynArray *&Value)
{
	init_func
	map[Tag].clear();
	Value=&map[Tag];
	_return(OK)
	exit_func
	_return(FAIL)
}

RESULT CTLVCreate::setValue(BYTE Tag,ByteArray &Value)
{
	init_func
	map[Tag] = Value;
	_return(OK)
	exit_func
	_return(FAIL)
}

RESULT CTLVCreate::getBuffer(ByteDynArray &Value)
{
	init_func
	uint32_t dwSize=0;
	tlvCreateMap::iterator it=map.begin();
	while (it!=map.end()) {
		if (it->second.size() < 0xff)
			dwSize += (uint32_t)it->second.size() + 2;
		else
			dwSize += (uint32_t)it->second.size() + 2 + sizeof(uint32_t);
		it++;
	}
	Value.resize(dwSize);
	uint32_t dwPtr = 0;
	it=map.begin();
	while (it!=map.end()) {
		Value[dwPtr]=it->first;
		dwPtr++;
		if (it->second.size()<0xff) {
			Value[dwPtr] = (uint8_t)it->second.size();
			dwPtr++;
		}
		else {
			Value[dwPtr]=0xff;
			dwPtr++;
			uint32_t dwSize = (uint32_t)it->second.size();
			Value.copy(VarToByteArray(dwSize), dwPtr);
			dwPtr += sizeof(uint32_t);
		}

		Value.copy(it->second, dwPtr);
		dwPtr += (uint32_t)it->second.size();
		it++;
	}
	_return(OK)
	exit_func
	_return(FAIL)
}
