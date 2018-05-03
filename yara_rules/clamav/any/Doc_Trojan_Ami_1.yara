rule Doc_Trojan_Ami_1
{
strings:
	$a0 = { 712c2031292c20313829203d202246756e6374696f6e204d6174697a4d652829 }

condition:
	$a0
}

        
