rule Win_Trojan_Lineage_242
{
strings:
	$a0 = { d1225d5103bec5a227efdac18a30bbdeccc3eb412f05bfe137a0f67fcffb2fc31958e5bdacb4c11306aeca6148abcf182ea59d48e65742db93d24392603e27d5555519da88631daf46564aed8ba036c911c793df7cbc5e5d668cfa8b }

condition:
	$a0
}

        
