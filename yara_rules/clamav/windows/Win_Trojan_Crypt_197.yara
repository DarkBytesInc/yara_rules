rule Win_Trojan_Crypt_197
{
strings:
	$a0 = { 5589e583ec4e57c704247089b704033d6194400039d6eb1fb80d93400089c289f02b0201f6ff15141040 }

condition:
	$a0
}

        
