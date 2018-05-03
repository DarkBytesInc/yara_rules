rule Doc_Trojan_Rash_2
{
strings:
	$a0 = { 6e616d203d206e616d202b204d6964284e61626f722c20496e74286b6b292c203129 }
	$a1 = { 5072696e742023312c202027cff0e8fff2edeee920f0e0e1eef2fb27 }

condition:
	$a0 and $a1
}

        
