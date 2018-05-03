rule Win_Worm_Bustoy_1
{
strings:
	$a0 = { 6a0168409040008bcee852fcffff6a00684090400055ffd36a0068409040008bcee83afcffff6a006840904000ff15bc804000 }

condition:
	$a0
}

        
