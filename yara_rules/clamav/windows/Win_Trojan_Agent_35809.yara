rule Win_Trojan_Agent_35809
{
strings:
	$a0 = { 89ff8b442404505d55ff15d044410083ec048904245b83fb00751e5089e05068f30000005050 }

condition:
	$a0
}

        
