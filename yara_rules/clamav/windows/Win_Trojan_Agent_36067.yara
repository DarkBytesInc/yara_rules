rule Win_Trojan_Agent_36067
{
strings:
	$a0 = { feffff014dbc21c84821c1ff8d34feffffff8dccfdffff29c01385d8fdffff098d80fdffff2b8598feffff81e90005000011855cfdffff298598feffffb99900000081c00003000021c831c829c8ff8d34ffffff81c08200000048138d9cfeffffb9d107 }

condition:
	$a0
}

        
