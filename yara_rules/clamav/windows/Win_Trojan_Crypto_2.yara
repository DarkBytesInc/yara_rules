rule Win_Trojan_Crypto_2
{
strings:
	$a0 = { 2e43727970746f202d2077656c636f6d6520746f206d7920776f726c642e2e2e00e818000000466972 }

condition:
	$a0
}

        
