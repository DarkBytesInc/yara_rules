rule Win_Trojan_Zbot_1253
{
strings:
	$a0 = { 89ff8b44240483ec048904245d55ff15dc71410083ec048904245b83cb0183fb01751d83ec04890c2489e1bbfb000000535151ff }

condition:
	$a0
}

        
