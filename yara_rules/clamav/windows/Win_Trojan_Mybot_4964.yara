rule Win_Trojan_Mybot_4964
{
strings:
	$a0 = { 6722d14dc169954b109e010f1f83d76e4e0efd00e88ecf495b57d344447564395582351bcbcdd950bdffed5090d45d20f624fb0379b7c3e90a9346fc13e137aa1b7779dfba92856320fda2d4ed40 }

condition:
	$a0
}

        
