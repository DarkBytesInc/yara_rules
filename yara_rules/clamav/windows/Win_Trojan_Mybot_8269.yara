rule Win_Trojan_Mybot_8269
{
strings:
	$a0 = { b760670c57b0ad1a23dc3285fce0e43b99101ee34c330e4f5d0a16f9cc488f751a068739359665d046efa4d695ac81beee023b9a6b85647c4c64a757d75d14ddb30c855c1754 }

condition:
	$a0
}

        
