rule Win_Trojan_SVA_1
{
strings:
	$a0 = { ec83c4f4894df48955f88945fc6a00668b0d3ca4440033d2b848a44400e8dc80ffff8be55dc304000000ffffffff24000000cdc520c7c0c1d3c4dcd2c520cfc5d0c5c7c0c3d0d3c7c8d2dc20cacecccfdcded2c5d02100000000558bec83c4f48955f48945fcb9e4a444 }

condition:
	$a0
}

        
