rule Win_Trojan_Hupigon_1635
{
strings:
	$a0 = { c630b608dfc07f0dfad6c69ea9a2b02cb58fbf695002d733191c614b1e0d1052a09c48c526ce280121f7d15fbf7efbac1d555fe12140454d4ba07ffa89deceb4e3adbafb9e5fecfe835b9832e865f041f3616fd51dddbe1eea18be939e45cda100d51d9052f097b3fb }

condition:
	$a0
}

        
