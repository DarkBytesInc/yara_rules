rule Win_Trojan_Limp_1
{
strings:
	$a0 = { 6578746e616d653d22687474226f726578746e616d653d2261737022[0-73]6c696d70636f636b }

condition:
	$a0
}

        
