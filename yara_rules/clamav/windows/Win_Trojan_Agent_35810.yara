rule Win_Trojan_Agent_35810
{
strings:
	$a0 = { 617363286d69642864612c692c312929222b766263726c662b226966207869616e }

condition:
	$a0
}

        
