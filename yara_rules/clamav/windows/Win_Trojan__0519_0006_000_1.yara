rule Win_Trojan__0519_0006_000_1
{
strings:
	$a0 = { b9a5008d960000cd21b440b944028d969303cd21b8004233c933d2cd21b4408d96cf02b91a00cd21 }

condition:
	$a0
}

        
