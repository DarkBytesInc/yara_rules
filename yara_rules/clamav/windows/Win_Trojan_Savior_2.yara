rule Win_Trojan_Savior_2
{
strings:
	$a0 = { e801000000e95d83ed08b800000000bb00000000b9bd0100005531852007000083ed0403c3c1d303e2f05d9090 }

condition:
	$a0
}

        
