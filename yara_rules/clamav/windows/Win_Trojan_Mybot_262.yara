rule Win_Trojan_Mybot_262
{
strings:
	$a0 = { 6f576f6f445c496eea93f94e6c67a12c6a477323e0ac08477072766b6e613bd164754927ec8672799feca44b619102fd3364305ce897e5 }

condition:
	$a0
}

        
