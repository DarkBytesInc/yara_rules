rule Win_Trojan_Bancos_1043
{
strings:
	$a0 = { af95e27835bdc9d261439e8de7b9130998486ed1d6b2c910b2e8fb7c5a7fa3abe830629c960f71faa81c5acd506daca93b66eadee6f38abda0dd4bed67b06dd048a75b3ecf719f9e3f78d5595a6ba85318a4f80bc6aac4c7 }

condition:
	$a0
}

        
