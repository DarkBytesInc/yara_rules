rule Win_Trojan__0186_0006_000_1
{
strings:
	$a0 = { 2d04002e89861701b4408bd5b9570190cd21b8004233c933d2cd21b4408bd581c21501b90400 }

condition:
	$a0
}

        
