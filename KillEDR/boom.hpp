#pragma once
#include <stdint.h>
#include <iostream>
#include <windows.h>

#include "utils.hpp"

class boom
{
public:
	static boom* instance();
	BOOL kill(const wchar_t *name);

private:
	boom() {};
	~boom() {};
	static boom* _instance;
};

