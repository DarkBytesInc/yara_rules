rule Win_Trojan_Lineage_341
{
strings:
	$a0 = { 7521177967cca3d0cedbc5deb2e0e2a9553aea29da31636d0cddbf7967ccdbd0cedbc5deb2e0e2a95720ee766f7f27ea64af02a8dd80ea29317263ac6ddf11d66674862b3324eec1b134ee29b4e4e1ac4d25ee298f20ef293117117fbca102d5cedbb979 }

condition:
	$a0
}

        
