rule Win_Worm_Nyxem_9
{
strings:
	$a0 = { 807c2408010f85c201000060be155018228dbeebbffeff57eb109090909090908a0646880747 }

condition:
	$a0
}

        
