rule Win_Trojan_F_14
{
strings:
	$a0 = { 33c0424a8ec0b83b002687060c00424a508cc8424a2687060e0050424acc58424a9d582687060e0058424a26 }

condition:
	$a0
}

        