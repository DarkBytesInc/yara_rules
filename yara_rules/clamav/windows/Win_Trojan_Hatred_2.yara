rule Win_Trojan_Hatred_2
{
strings:
	$a0 = { 74105e5f5f83c70483c604833e007417ebd75e5f5f528b36ffd60f23c00bc07406610f21c0f8c36133c0f9c3608bd88bf866813f4d5a753d8b7f3c81ff00 }

condition:
	$a0
}

        
