rule Win_Trojan_Obfus_7
{
strings:
	$a0 = { 6681a424f8feffff000066818c24f8feffffa6266681a424fafeffff000066818424fafeffff7394baa62673940fcac78424b8ffffff379ac156bb379ac156c78424a8ffffff459b4a1e81eb459b4a1e6681a424f4fdffff00006681a424f6fdffff0000818c24f4fdffffb2a6f040bdb2a6f040c7842418feffff5c748f7d }

condition:
	$a0
}

        
