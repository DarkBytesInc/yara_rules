rule Win_Trojan_Exec_3
{
strings:
	$a0 = { 636c6f636b24000e2f432044495220202020202020200d008db62100b86201ffd08db629008bbe06 }

condition:
	$a0
}

        
