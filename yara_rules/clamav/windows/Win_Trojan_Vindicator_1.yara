rule Win_Trojan_Vindicator_1
{
strings:
	$a0 = { 35cd218d3eab0239df75098bf7b90a00f3a67444891eb9028c06bb020e58488ed8a103002d6000a303000e1fa102002d6000a302008ec031ffbe0001b9 }

condition:
	$a0
}

        
