rule Win_Trojan_Agent_33065
{
strings:
	$a0 = { 700d7d95089550891c39cc6cbf2d35f618c70f24463fff97faff900d1d160cc608205f83f906c487dd762d2a000cbbc2cc45ff7fe9ff3bb820d786bfce75b83281898d1643a1e738a156 }

condition:
	$a0
}

        
