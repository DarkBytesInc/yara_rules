rule Win_Downloader_Swizzor_596
{
strings:
	$a0 = { ffa42708ca9bdc07a643ba0f0bf972da76bb484b60410f438cc581bbe637fffbc30b01ea83b2be82aa8f3a216463cfc5c7ccfe8a4bced75560962dc471578bc66c64cd7bee2e32d5fca94e40bd5e2cfee77190bd12a661e05cff1806e1a4587c1779f134ce4818bbdd }

condition:
	$a0
}

        
