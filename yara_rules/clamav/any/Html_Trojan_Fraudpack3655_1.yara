rule Html_Trojan_Fraudpack3655_1
{
strings:
	$a0 = { 558becb8940000002be089042454ff15343006108b44240481c4940000006a0050e855000000c3eb4850ff }

condition:
	$a0
}

        
