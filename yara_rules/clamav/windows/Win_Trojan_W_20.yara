rule Win_Trojan_W_20
{
strings:
	$a0 = { 525657e800005b83eb09551e068cd08ed88ec081ec80028bec899e0802e815007503e8030181c48002071f5d5f }

condition:
	$a0
}

        
