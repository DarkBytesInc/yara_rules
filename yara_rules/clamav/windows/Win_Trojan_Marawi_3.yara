rule Win_Trojan_Marawi_3
{
strings:
	$a0 = { 8cc88ed8e84dfd750bb409baab0ccd21b44ccd21fc060e07be8d04b94800e897f4 }

condition:
	$a0
}

        
