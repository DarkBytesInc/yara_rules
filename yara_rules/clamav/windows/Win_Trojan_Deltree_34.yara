rule Win_Trojan_Deltree_34
{
strings:
	$a0 = { 64656c74726565202f7920633a5c616f6c357e312e30 }
	$a1 = { 78636f70792064656c352e62617420633a[0-27]73746172747570 }

condition:
	$a0 and $a1
}

        
