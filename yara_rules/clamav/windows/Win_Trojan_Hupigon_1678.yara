rule Win_Trojan_Hupigon_1678
{
strings:
	$a0 = { 0489d31e1b557bd299fc628e65ff5933c7b7f9ef41fa94adc17ac0634c8ddb8aef61d2d4bab7fb4cccfd8b909d8b6359f23d6682ce7c7d7d6c6f3a2d0fdf7fb375c8c63158be9104b921ba96a1e904345c459afab32415a4d03868154f2ed3 }

condition:
	$a0
}

        
