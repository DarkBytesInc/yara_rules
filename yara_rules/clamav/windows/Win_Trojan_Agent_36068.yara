rule Win_Trojan_Agent_36068
{
strings:
	$a0 = { ffff19458cff8d18feffff2b9508feffff83fa7d762a3355b829c001d021d01385dcfeffff0b8518ffffff424a4a199544feffff1995f4feffff2b9544feffff21d001d08b8d9cfeffff1b8de4fdffff29955cfeffff239594feffff4131d231ca01ca81 }

condition:
	$a0
}

        
