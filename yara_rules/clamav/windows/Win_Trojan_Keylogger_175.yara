rule Win_Trojan_Keylogger_175
{
strings:
	$a0 = { 5379735f4b65796c6f67000d0117005359535f4b45594c4f4720312e3320414456414e434544 }

condition:
	$a0
}

        
