rule Win_Trojan_WordMacro_1
{
strings:
	$a0 = { 0e5669724e616d655061796c6f61641269025a24641a1b64641c690a56496e7374616c6c6564642c2d18266469034343240c674d81056a0a5669724e616d65446f63066452690a }

condition:
	$a0
}

        