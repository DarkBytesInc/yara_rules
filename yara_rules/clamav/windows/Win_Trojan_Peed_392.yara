rule Win_Trojan_Peed_392
{
strings:
	$a0 = { 8d4c2000e84b000000e97e000000558d6c24008d55088b5422008d028b442000c9c204005029d8 }

condition:
	$a0
}

        
