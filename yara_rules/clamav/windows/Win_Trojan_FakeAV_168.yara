rule Win_Trojan_FakeAV_168
{
strings:
	$a0 = { 33c9b8??20400083ec7c518bd403085251e8??0600005883c47c0496750420c07401c360e9??0400000000008bff55 }

condition:
	$a0
}

        
