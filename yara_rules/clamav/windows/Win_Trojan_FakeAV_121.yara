rule Win_Trojan_FakeAV_121
{
strings:
	$a0 = { d8feffff899524feffff0995d8fdffff09959cfeffff119548fdffff42399568ffffff73428b45c02185b4fdffff31d021d0038524ffffff83fa00722a1395e8feffff0b9598feffff2b9564fdffff19952cffffff899528fdffffff8590fdffffff8d7c }

condition:
	$a0
}

        
