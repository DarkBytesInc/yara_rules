rule Win_Trojan_VB_35_2
{
strings:
	$a0 = { 466f726d32000000436f62726155706c6f61646572000000593ef03e8be86740b41c7d2af94ee39755396538851d0a4faff0bec9 }

condition:
	$a0
}

        