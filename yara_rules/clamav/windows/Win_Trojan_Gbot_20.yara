rule Win_Trojan_Gbot_20
{
strings:
	$a0 = { 558bec81ec600400006a006a006a00e85000000083e804400fafc2906a065a25ff0000002e663db8fefcf2747c6a006a016a146a }

condition:
	$a0
}

        
