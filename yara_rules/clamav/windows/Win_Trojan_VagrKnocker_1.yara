rule Win_Trojan_VagrKnocker_1
{
strings:
	$a0 = { 537064476f436c69636b0f5466726d46696c654d616e616765720600743a4200b0bc4500f4c84600 }

condition:
	$a0
}

        
