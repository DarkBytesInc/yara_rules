rule Win_Trojan_Dialer_232
{
strings:
	$a0 = { 6765747375626469616c65722e706870343f646e723d0000474554003231372e3136302e3134302e363700007867656e697573004166783a3430303030 }

condition:
	$a0
}

        