rule Win_Trojan_Lineage_487
{
strings:
	$a0 = { dcf02e003d43fb56aae1320ae73313180940ae383bb37bbb0cfa0ce12aae2bec47ba58e31634759fe3d5cbae1a6ddea07638cbc189f37adbee826f44f6e7b14499220d25bd4ef91138aad11c8fbbfd6d2adc1a9c8a393da5ad08ea275066ce5058e02c9a2708f7dc18e3e24aa2fc9d835448656e912322c9ea5f77aeb11bb6ef }

condition:
	$a0
}

        
