rule Win_Trojan_Crypt_177
{
strings:
	$a0 = { 509bdfe058565e535383c40455e8de010000f7e579775371421aabf9956d9953ac03c7627dd814725c8c7f952c3c82ac22b2692be5 }

condition:
	$a0
}

        
