rule Win_Trojan_Dialer_163
{
strings:
	$a0 = { 6f722c203c2fee46d9f668616c476430006f7065dbf7efc6b35c032557494e444952250f771f38ef2e3cff36636f6d2e737973445f5547 }

condition:
	$a0
}

        
