rule Win_Trojan_MIPT_2
{
strings:
	$a0 = { 5633f6505351525657061e2e8b3601015681ee010081c69b022e8b142e891600012e8a54022e88160201b4ffcd }

condition:
	$a0
}

        
