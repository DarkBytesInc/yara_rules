rule Unix_Tool_13730_1
{
strings:
	$a0 = { eb0f31c0b00a5bcd8031c0b00131dbcd80e8ecffffff2f6574632f736861646f77 }

condition:
	$a0
}

        
