rule Win_Trojan_Mybot_5080
{
strings:
	$a0 = { 38fabc5f3384fea764f3ad336ba1b8adcb830a5e61fffe3367f25fb93a2f08ac39fb0aee63feb0a43684adb868a2063338fabc5f3394fea764f3ad436ba1b8adcb930a5e61fffe4367f25fb93a3f08ac39fb0afe63feb0a43694adb868a2066d38fabc5f33c2fea764f3ad776ba1b8adcbc30a5e61fffe7567f25fb93a7506ac }

condition:
	$a0
}

        
