rule Win_Trojan_Nilage_1
{
strings:
	$a0 = { ff25fca040008bc0ff25f8a040008bc0ff25f4a040008bc0ff25f0a040008bc0ff253ca140008bc0ff2538a140008bc0ff2534a140008bc0ff25eca040008bc0ff25e8a040008bc05383c4bcbb0a00000054e8b9fffffff644242c0174050fb75c24308bc383c4445bc38bc0ff25e4a040008bc0ff25e0a040008bc0ff25dca040008bc0ff25d8a040008bc0 }

condition:
	$a0
}

        