rule Win_Trojan_KillMBR_6
{
strings:
	$a0 = { 0e1fbe3c0133c98a3c80f7ca883c464181f900f075f1be2b01bf00ffb96400f3a48b0e290151e9d1fd3c0059be000103f1b900febf0001f3a4e9ed017ec97acb784a7cca73cbcaf9119a9f41260d8cc8ca7297cd07d9 }

condition:
	$a0
}

        
