rule Win_Tool_AttKit_1
{
strings:
	$a0 = { 61746b000000000041747461636b20546f6f6c204b6974202841544b29 }

condition:
	$a0
}

        
