rule Win_Trojan_Deltreey_3
{
strings:
	$a0 = { 64656c202a2e6578652064656c202a2e636f6d2063645c2064656c74726565202f792070726f6772617e31 }

condition:
	$a0
}

        