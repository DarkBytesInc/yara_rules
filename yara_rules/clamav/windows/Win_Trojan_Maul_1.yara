rule Win_Trojan_Maul_1
{
strings:
	$a0 = { 67b0b38f7e8e2cae9fdbf88bcaa4ff9377c675bd4f40c8b7d07f3570377cba8faf9ab3f57442b55fcd45fc7de7c3d217e652dfb5a54eb3d72275a78d572e45a8b2faadf121d8cdff07bbc1410100000802b16b411dde86b07f0b24851bfc4a8dccca07638a211280300cc0ca4f6a }

condition:
	$a0
}

        
