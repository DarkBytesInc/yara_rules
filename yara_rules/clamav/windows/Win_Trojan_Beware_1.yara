rule Win_Trojan_Beware_1
{
strings:
	$a0 = { 4d204265576172650d0a40676f746f2052756e4265576172650d0a3a436f6d6f6e20252542655761726525250d0a4063747479206e756c252542655761726525250d0a6966205e2525313d3d5e42655761726542415420676f746f204265576172654241540d0a6966205e2525313d3d5e42655761726557425420 }

condition:
	$a0
}

        