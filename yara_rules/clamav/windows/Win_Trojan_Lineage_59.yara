rule Win_Trojan_Lineage_59
{
strings:
	$a0 = { 53bbf4a64000a1f8a64000506a00e8c5aeffff8b038b400c85c0740750ff1518a740008b0333d289500c8b038b401085c0740750ff1518a74000 }

condition:
	$a0
}

        
