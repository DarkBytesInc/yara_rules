rule Win_Trojan_Packed_172
{
strings:
	$a0 = { 6033f681f620304000832d??204000046a026a0056e8????000083e8037c0b807e05450f84??040000cc80460545ebe0 }

condition:
	$a0
}

        
