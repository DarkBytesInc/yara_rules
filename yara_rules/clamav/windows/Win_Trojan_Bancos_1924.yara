rule Win_Trojan_Bancos_1924
{
strings:
	$a0 = { b7ad98a2ed44be57aa3ae258ceb977023102da53c1af0cc0e32fa05dab00cc798e5753365bab5068d5ea18360839cd943ff06f1bf5b840e2976b1d9247c8f4b717b71350341504a3feefc5968a8af498e80dbfcb20caa27fc842 }

condition:
	$a0
}

        
