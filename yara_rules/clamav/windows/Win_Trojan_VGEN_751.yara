rule Win_Trojan_VGEN_751
{
strings:
	$a0 = { 5d81ed0301b430cd213c04727a501e33c08ed8a1fd033d5346746c1f58e871011e5848501f832e030032832e120032 }

condition:
	$a0
}

        
