rule Win_Trojan_Crypt_202
{
strings:
	$a0 = { 51230d890a0110310dad0901108f05350601108b0d350601100f87e2000000e87e0000001341c5c750af }

condition:
	$a0
}

        
