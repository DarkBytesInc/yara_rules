rule Win_Trojan_Bancos_1462
{
strings:
	$a0 = { bdd595be9dc839dff891cf0df15ae5a551d97dc00cf45e260b529f1726a2999cabe6e2f0f1eed857ef1589debd00629ddcb7d64f45a9d716207431409b6794da6e26231bcfd0b03ed43ff9cfe87c440abd7acf648a0973dd76a0 }

condition:
	$a0
}

        
