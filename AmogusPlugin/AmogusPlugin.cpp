#include  "AADebugBad.h"

int main()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN); // for fun
	SetConsoleTitleW(L"[SecureEngine] advanced anti-anti-anti-debug tool");//themida mem 
	
	std::cout << "Is bad hook NtSystemDebugControl ->\t" << bad_code_detector::is_system_debug_control_hook() << '\n';
	std::cout << "Debug flag is hooked ->\t" << bad_code_detector::is_debug_flag_hooked() << '\n';
	std::cout << "Breakpoint bad ->\t" << bad_code_detector::is_bad_hide_context() << '\n';
	std::cout << "Thread hide bad ->\t" << bad_code_detector::is_bad_hide_thread() << '\n';
	std::cout << "Debug object bad  hook ->\t" << bad_code_detector::is_debug_object_hooked() << '\n';
	std::cout << "Number object bad  hook ->\t" << bad_code_detector::is_bad_number_object_system() << '\n';
	std::cout << "Is bad close handle ->\t" << bad_code_detector::is_bad_close_handle() << '\n';

	std::cin.get(); 
	return NULL;
}