rule Win_Trojan_Lmir_49
{
strings:
	$a0 = { ba005641008bc3e80cf9ffffba0c5641008bc3e888f7ffffba1c5641008bc3e8f4f8ffff53e826edffff33c05a595964891068b45341008d45dcba09000000e8e8edfeff8d4510e8bcedfeffc3e956e7feffebe35b8be55dc20c0000ffffffff1a00000046726f6d3a227768626f }

condition:
	$a0
}

        
