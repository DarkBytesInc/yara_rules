rule Win_Trojan_Rape_14
{
strings:
	$a0 = { 512e8b16010181c203018bf28bea83c5349055eb00b000563c00741683c63490b9b1018a24518ac8d2c4598824fec046e2f15ec3 }

condition:
	$a0
}

        
