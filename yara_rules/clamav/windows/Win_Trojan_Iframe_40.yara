rule Win_Trojan_Iframe_40
{
strings:
	$a0 = { 7768696c6528633c3d73[0-37]2974656d703d74656d70[0-48]2874656d70293b74 }
	$a1 = { 7372633d222e2f71756f74612e706870 }

condition:
	$a0 and $a1
}

        
