rule Win_Trojan_Ceckno_3
{
strings:
	$a0 = { 85db740f6a006a0068f500000053e8acd9ffff6a0068f06c1413e870d9ffff85c074086a0050e89cd9ffff6a0068d86c1413e858d9ffff85c0740f6a006a006860f0000050e875d9ffff }

condition:
	$a0
}

        
