rule Win_Trojan_Mybot_5461
{
strings:
	$a0 = { 5b3257503ad1fc664dcf7b15d5123b07526984d7c0e4f141b9610ae157158eaab83b869bee0da7e2fd14ff8b94d54fa332cca3314cd4d6394f9157e3041dd6ebbff9f1bc37cde149ebc9759df91dcc3bac430ffc4be9358dff9c957f4451eb25ebc68dfdf9b2b2e78c }

condition:
	$a0
}

        
