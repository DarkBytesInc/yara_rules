rule Win_Trojan_Crypt_183
{
strings:
	$a0 = { 68af664500e84e0e0000683c5a4500e8611f00003cde7b53[0-160]7344617448546f446f4854696d65 }

condition:
	$a0
}

        
