rule Win_Trojan_Dialer_799
{
strings:
	$a0 = { 77c8de48bc28e46e732bb4bb66bc44ce99e22b87a17cca522cac6985f6260aa1a15f96442c7c1742384b097019b0468e4f4bb0fa9d059ed055836af65f74abfd0c0d227e8eb2e02675bcbe9e2505865b15b5f47016b1819669dd1ac048d9f708297f9774f97d6a8a2967c6227e1d29d8d8491ab1532c00a413cbe201d880e2912a1c15bb8dbd1f15f3d979d5 }

condition:
	$a0
}

        