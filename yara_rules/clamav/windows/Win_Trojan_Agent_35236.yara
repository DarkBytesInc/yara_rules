rule Win_Trojan_Agent_35236
{
strings:
	$a0 = { 1b7eb8ad3d7a97187c33395fa14eccedb3b6a23b909b05fd6ab7601ac79f18e09cc53fd78c58a3a63134cc7b85a8b9ade526e7f38fcbf6092dc7368c900063a806b7d2927d02946413497cd7c48a69f96e9d32bd75e6 }

condition:
	$a0
}

        
