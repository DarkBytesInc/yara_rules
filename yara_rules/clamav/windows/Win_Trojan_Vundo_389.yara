rule Win_Trojan_Vundo_389
{
strings:
	$a0 = { eb061cd1b14ae2a560e8030000004919015883c008eb3bc16bcd87b903eb4385df311bbdb729b3750fa1cbade79963653f117b9d170913556f812b8d4779c3459ff1db7d77e97335cf618b6da7592325ffd1ebc93beb3f5dd7c9d3152f41eb4d0739ebf1 }

condition:
	$a0
}

        