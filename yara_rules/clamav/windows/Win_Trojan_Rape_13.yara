rule Win_Trojan_Rape_13
{
strings:
	$a0 = { 2e8b16010181c2030189d68bea81c5340055eb00b000563c00741681c63400b9b0018a245188c1d2c4598824fec046 }

condition:
	$a0
}

        
