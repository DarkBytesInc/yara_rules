rule Win_Trojan_Lineage_250
{
strings:
	$a0 = { 93f0cda12c8212e791c4f4db73a80041c186fc079bc3bdc7910f17d6eca6c4652960e69fad08f1aca9bac8f3803bb14db573ff5a98dcebd5c924973b31bf7cf52d4fe5437033aade5f18f00808afbd3da4c76b422d10db3d329bd2a4 }

condition:
	$a0
}

        
