rule Win_Trojan_Savior_4
{
strings:
	$a0 = { 9c60e8010000009a5d83ed08b800000000bb00000000b9d00100005531856c07000083ed0403c3d1d3e2f15d909090 }

condition:
	$a0
}

        
