rule Win_Trojan_Jerk_6
{
strings:
	$a0 = { 4630000d010e004a65726b314e2773204e5439 }
	$a1 = { 4900430035005c00560049005200550053005c004e00 }

condition:
	$a0 and $a1
}

        
