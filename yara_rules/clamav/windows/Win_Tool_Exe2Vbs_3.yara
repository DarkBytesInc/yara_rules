rule Win_Tool_Exe2Vbs_3
{
strings:
	$a0 = { 7465787466696c65203d2022766273657865637574656d616b65722e65786522 }

condition:
	$a0
}

        
