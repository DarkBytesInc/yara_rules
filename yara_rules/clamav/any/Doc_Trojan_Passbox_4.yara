rule Doc_Trojan_Passbox_4
{
strings:
	$a0 = { 54657874426f78312e50617373776f726443686172203d20222a22 }
	$a1 = { 4c6162656c322e43617074696f6e203d2022496e7369726120612073656e68612070617261206162726972206f206172717569766f22 }

condition:
	$a0 and $a1
}

        