rule Win_Trojan_Espionage_1
{
strings:
	$a0 = { 45007300700069006f006e006100670065002000480054005400500020005300650072007600650072 }

condition:
	$a0
}

        