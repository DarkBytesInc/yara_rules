rule Win_Trojan_Small_4100
{
strings:
	$a0 = { e834000000c8000020e841000000c2300031c08b520c50e80200000052c383042408ebf805386762 }

condition:
	$a0
}

        