rule Win_Trojan_Lineage_325
{
strings:
	$a0 = { 4040c49f4baf0f9c65a2471909e3eb864b00e645b6ce8c80e21e149d5e8972900d4c84a0f4b3507d6342f9c6646be83e6919d467ee1e1ec5c5d0188e69d03833c9fa8466e101be3e4dca7e692b888c954f28e32b46ef910a0eefef666b58e7 }

condition:
	$a0
}

        