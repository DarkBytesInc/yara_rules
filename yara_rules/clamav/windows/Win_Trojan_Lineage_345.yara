rule Win_Trojan_Lineage_345
{
strings:
	$a0 = { 3920e8d6ba0ed20ba8e366a201f400ac7dcf27db9a152f5b151ea61fc3f27a0ba8e31ea201f400ac7dcf27db980f2b04a050e298ab80c7da12af2f5bfe5da6dea2f0d4a4a95b4359fc0b2bb34e042b5b7bcb24de820a2b5b400f2a5bfe38d40d738ec7a7 }

condition:
	$a0
}

        
