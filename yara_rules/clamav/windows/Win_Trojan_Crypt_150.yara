rule Win_Trojan_Crypt_150
{
strings:
	$a0 = { 80309983e90183c00185c975f3c3cccc8b54240885d274208b4c24048d6424008a0183ea0184c07904247feb020c80880183c10185d275e8c3cccccccccccccc }

condition:
	$a0
}

        
