rule Win_Trojan_Peed_270
{
strings:
	$a0 = { 682225ab0089f25be84d00000068141900005981c11014000081c11419000068 }

condition:
	$a0
}

        
