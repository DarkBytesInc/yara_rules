rule Win_Trojan_Startpage_448
{
strings:
	$a0 = { 6d73746d70786d6c646f776e2e657865[0-16]53746172742050616765[0-82]4578706c6f7265725c4d61696e }

condition:
	$a0
}

        
