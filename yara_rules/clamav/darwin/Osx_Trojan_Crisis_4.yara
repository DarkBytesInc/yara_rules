rule Osx_Trojan_Crisis_4
{
strings:
	$a0 = { 2f55736572732f677569646f2f50726f6a656374732f6472697665722d6d61636f732f6d63686f6f6b2e63 }

condition:
	$a0
}

        
