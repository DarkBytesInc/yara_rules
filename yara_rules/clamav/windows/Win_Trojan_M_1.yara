rule Win_Trojan_M_1
{
strings:
	$a0 = { dacd213d73197503e98700505351525657061eb452cd21268b57fe8ec233db2603570383c2022e891601002ec6 }

condition:
	$a0
}

        
