rule Win_Trojan_Bancos_1310
{
strings:
	$a0 = { a8f83a018fba4982197a49e568e093677a28fc9063a796e8c8e594d93ce30eb3e69086946b39325f1aaf0e7d00e1911f9c723c98d6ccc7fef32190bd63ef68741038f316b04fa12235307020a808b0db323d }

condition:
	$a0
}

        