rule Win_Trojan_Delf_2350
{
strings:
	$a0 = { 60be005044008dbe00c0fbffc7878c5008007618d17257eb11909090909090908a064688074701db75078b1e83eefc11 }

condition:
	$a0
}

        
