rule Win_Trojan_Irate_1
{
strings:
	$a0 = { 01b90200e8bb01813607012345813e070179087427813e07016e1f741f813607012345e9ce00 }

condition:
	$a0
}

        
