rule Win_Trojan_Small_3833
{
strings:
	$a0 = { 3c7824bbc4368d782f9cf815151acdca069c00f81308362ab8cdb31d8cae4b1f86baf8eb0de64a7bae762ff142c61c41cc3a85ba7b61e80d8351f2652c5b34635ec0a2550901d535bee9ee8ddbbd030cb27cdb598b0bf86f50dc3d17e2e9d171b718d30ca08b5d273b }

condition:
	$a0
}

        
