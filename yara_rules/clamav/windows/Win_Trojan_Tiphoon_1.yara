rule Win_Trojan_Tiphoon_1
{
strings:
	$a0 = { 6f6f6e201168617320737765707420796f75722050439a000081009a000015005589e5bf00000e }

condition:
	$a0
}

        