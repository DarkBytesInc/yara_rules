rule Win_Trojan_Bancos_1161
{
strings:
	$a0 = { 0dd7a3ac7ca6893f7b152a4b7f12a6ed33edf1ecc06026d68bd42027cbeddd890a07e2cd1a960ee979f6bd827296b27f15db3c09c46f4abbef5a73b64946289a0f138f0c6f4abfdda790e6637d7122a8c43040b24ef1644aa2e8572fd349f3 }

condition:
	$a0
}

        
