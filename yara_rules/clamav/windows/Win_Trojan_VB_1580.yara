rule Win_Trojan_VB_1580
{
strings:
	$a0 = { 73746900696c6f736f7068e91739cb5e935c44a4e781a3bfee59d6ff772ec4bff92949bb1ee305dfce4505ffcc3100077d99ea88d60dca45b010f6de4e781dfeef87257d34274b4aa2ee87c77a248e023a4f }

condition:
	$a0
}

        
