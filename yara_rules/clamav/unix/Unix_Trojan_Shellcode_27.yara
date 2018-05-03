rule Unix_Trojan_Shellcode_27
{
strings:
	$a0 = { eb489affffffff07ffc35e31c08946b48846b988460789460c31c050b08de8dfffffff83c40431c050b017e8d2ffffff83c40431c0508d5e08538d1e895e0853b03be8bbffffff83c40ce8bbffffff2f62696e2f7368ffffffffffffffffff }

condition:
	$a0
}

        
