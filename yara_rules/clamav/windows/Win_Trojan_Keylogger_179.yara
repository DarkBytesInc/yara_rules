rule Win_Trojan_Keylogger_179
{
strings:
	$a0 = { 466f726d31000d0117005379735f4b65796c6f6720312e3220416476616e63656400 }

condition:
	$a0
}

        
