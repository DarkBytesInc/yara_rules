rule Win_Trojan_Agent_33081
{
strings:
	$a0 = { f7c8cdfc27e11b1201b0302375d1b9517146f299bb8c6d4097ca06c6094c00850a086589a09e5fe9eeeeae2bc4354e128b193589381108c01cfc65b6cef9b20b8b7e9d6a9e30a91f5fd8f9 }

condition:
	$a0
}

        
