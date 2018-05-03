rule Unix_Tool_13445_1
{
strings:
	$a0 = { eb185e89760831c088460789460c89f38d4e088d560cb00bcd80e8e3ffffff }

condition:
	$a0
}

        
