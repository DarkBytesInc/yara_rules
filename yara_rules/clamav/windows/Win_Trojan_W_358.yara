rule Win_Trojan_W_358
{
strings:
	$a0 = { 50975581eca30600008bec8d4510508d8791010000508d8797010000ff1083f8ff742090 }

condition:
	$a0
}

        
