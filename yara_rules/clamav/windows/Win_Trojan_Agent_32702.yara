rule Win_Trojan_Agent_32702
{
strings:
	$a0 = { e7396aa0183365626f2585fa504f053c7e5619fbbbc8bde1e62d9e36c7bde833a45ccc147035a6f011e16ce52635b513cbd182a29247da7b5e667a5b3279c97dd42986b0 }

condition:
	$a0
}

        
