rule Win_Trojan_Vgen_85
{
strings:
	$a0 = { b9de02bd880145315696314e96316e96f7c10100750142e2ed7c8586368989df162d0b9b6138382423bf43af30 }

condition:
	$a0
}

        
