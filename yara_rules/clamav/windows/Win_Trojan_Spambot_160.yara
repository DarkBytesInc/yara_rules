rule Win_Trojan_Spambot_160
{
strings:
	$a0 = { d22aa42a2d9f996053daf6398cbb7d76096c9cc6e17423f5ffffffffdd8dbc2f8ec41958bafe486f7797e4ab0500af696bc49600f58e16269a291cbcffffffffc8e2484b651772b560f4d0314e38d627848799509bab936e96e548fa27f6593cffffffff5d4b8c212c08c50fea58 }

condition:
	$a0
}

        
