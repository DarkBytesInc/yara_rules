rule Win_Trojan_bwg_1
{
strings:
	$a0 = { 6563686f206e??3d20202f2e6463632073656e6420246e69636b20433a5c[0-20]2e626174203e3e20433a }

condition:
	$a0
}

        
