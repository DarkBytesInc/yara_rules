rule Win_Trojan_VGEN_327
{
strings:
	$a0 = { 9a000085005589e5b800069acd02850081ec0006c7065e017927bfea041e57bf00000e5731c0509a700685009add0585 }

condition:
	$a0
}

        
