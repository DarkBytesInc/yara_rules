rule Win_Trojan_Gbot_14
{
strings:
	$a0 = { 558bff8bec81ec64040000c70424fffffffffc83642428008d85c0fcffff6800100000e85000000083e80303d183e100ba18000000b9fe00000023c166a9fd00 }

condition:
	$a0
}

        
