rule Win_Trojan_Gbot_13
{
strings:
	$a0 = { 558bff8bec81ec64040000c70424ffffffff8d85c0fcffff6800100000e84f00000083e80303d183e100ba18000000b9fe00000023c166a9fd000f8480000000 }

condition:
	$a0
}

        
