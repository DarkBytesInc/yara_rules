rule Win_Trojan_SillyC_169
{
strings:
	$a0 = { 9a008b04050001be3502033606018904b440b90800ba2f0203160601cd217209b801575a59cd21 }

condition:
	$a0
}

        
