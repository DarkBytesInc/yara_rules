rule Win_Trojan_Crisis_8
{
strings:
	$a0 = { 456c656d656e74277279[0-1]70656e6775694e733b2d2953696e67696e67486172654b726973686e615f }

condition:
	$a0
}

        
