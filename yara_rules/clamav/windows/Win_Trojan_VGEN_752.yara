rule Win_Trojan_VGEN_752
{
strings:
	$a0 = { 81ed0301b430cd213c04727c501e33c08ed8a1fd033d5346746e1f58e876011e5848501f832e03003290832e1200 }

condition:
	$a0
}

        
