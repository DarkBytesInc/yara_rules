rule Win_Trojan_Zbot_1252
{
strings:
	$a0 = { 89ff8b442404505d55ff15????410083ec048904248b1c2483c40483cb0183fb01751d5189e1bbf7000000535151ff15 }

condition:
	$a0
}

        
