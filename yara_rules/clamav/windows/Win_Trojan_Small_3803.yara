rule Win_Trojan_Small_3803
{
strings:
	$a0 = { e205e2345d10eada0844ab651d9affda424ee1ecde46edae6134b6a0e26499ae6934aaae1b9bf61de1957351082b72520c41edcd1210ba259e16427c449dfd21f61289e5424e79ae5934b2739664 }

condition:
	$a0
}

        
