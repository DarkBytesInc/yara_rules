rule Win_Trojan_Spambot_273
{
strings:
	$a0 = { c23c0888191e4789ffffffff0f38ec0549ababa61cab889f5880db02e5dbc20801baa357a7ea9e7fe1543a97ffffffff841b89e5f1adc92107c4547bfea7dfdcfb0f0a82cdcd764546d75dab95286062ffffffffe14f31aaff3877b082e34120e46e698e307be04c58161185b085 }

condition:
	$a0
}

        
