rule Win_Trojan_C_24
{
strings:
	$a0 = { 81ee030033c08ed88cc866c1e0108d840902668706040066a30400b0008bdeb99b012e020743e2fa2e3a84ee030f85 }

condition:
	$a0
}

        
