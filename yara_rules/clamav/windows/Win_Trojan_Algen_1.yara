rule Win_Trojan_Algen_1
{
strings:
	$a0 = { b05501a42a60cc15102c0c60c40502960be0bc1440df016c27a13a05809a82b02981305109704b425980fa4a52eb5dba30b86c2e1b0b86c2e1b0f3d1b0 }

condition:
	$a0
}

        
