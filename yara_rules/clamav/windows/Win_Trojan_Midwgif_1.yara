rule Win_Trojan_Midwgif_1
{
strings:
	$a0 = { 6c6f67696e6d69643d2573266e69636b69643d3026733d25730000006c6f67696e6d69643d2573266e69636b69643d3126733d2573000000504f535400000000 }

condition:
	$a0
}

        