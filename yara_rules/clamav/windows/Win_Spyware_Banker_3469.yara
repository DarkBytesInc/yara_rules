rule Win_Spyware_Banker_3469
{
strings:
	$a0 = { 4ee34900d5c325c8db20822b8da57aaca602cead3d2ca129ce85dc575347a3de063f7c9cb067e5ea7c2e78ed4afbdc9e33b1663ad73304d984278223df5fe08e49cde9d88956990f0e0bff1c388376c57f4319344bae0bd5cf268af08e20b7 }

condition:
	$a0
}

        
