rule Win_Trojan_W_14
{
strings:
	$a0 = { 4175746f436c6f73650100084175746f457865630100074175746f4e65770100084175746f4f70656e0100044b696c6c01000754686554696d6501001106000000044b494c4c000100074155544f4e45570002000754484554494d45000300084155544f45584543000400084155544f4f50454e000500094155544f434c4f5345 }

condition:
	$a0
}

        