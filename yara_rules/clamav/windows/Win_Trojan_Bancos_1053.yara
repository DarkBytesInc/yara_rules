rule Win_Trojan_Bancos_1053
{
strings:
	$a0 = { 64d179343450aaf2094144f4f1a2709d04ccbca447dba0b5ff88cb9c043e5ed37d53e9cc25e03a7bb4782b56b392960414a925e01fa7e19a88d8ae1fe7966e1cc451c134ee25dd8a4d31aab3e69796a324c8e00f90ae03d0 }

condition:
	$a0
}

        
