rule Unix_Tool_13669_1
{
strings:
	$a0 = { eb125b31c031c931d2b1b6b501b00f89530bcd80e8e9ffffff2f6574632f736861646f77 }

condition:
	$a0
}

        
