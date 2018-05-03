rule Win_Worm_Magistr_1
{
strings:
	$a0 = { 60e8060000008b642408eb0c2bdb64ff33648923ff03ebe813c5982bdb648f035be800000000 }

condition:
	$a0
}

        
