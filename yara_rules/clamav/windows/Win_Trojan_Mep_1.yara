rule Win_Trojan_Mep_1
{
strings:
	$a0 = { 33c08ec026a135053d4d457423bf3505be0001b92701fcf3a4b88c05268706840026a3c80033c0268706860026 }

condition:
	$a0
}

        
