rule Win_Trojan__0519_0006_002_1
{
strings:
	$a0 = { 9303b94402e867feb440b9a5008d960000cd21b440b944028d969303cd21b8004233c933d2cd21 }

condition:
	$a0
}

        
