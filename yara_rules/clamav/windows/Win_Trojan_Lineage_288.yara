rule Win_Trojan_Lineage_288
{
strings:
	$a0 = { 1cd67930da7138950205a2668b75ea4219451834d87cab32c8b60b0beb3c0efc2dacb6be362c6dfab9b67eb8c4beadf74b628759c2f7398ce994a90f2ccfcf63150c1aa15e43b0ed811c4686137631b112b2bae282cdc41bdfba4554 }

condition:
	$a0
}

        
