rule Win_Trojan_MURK390_1
{
strings:
	$a0 = { 66b8004098eb0566b8003f988b5d10e801000000c351506810002a00ff5500c32a2e45584500 }

condition:
	$a0
}

        
