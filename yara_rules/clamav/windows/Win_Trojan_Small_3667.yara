rule Win_Trojan_Small_3667
{
strings:
	$a0 = { 188d42d88c32819fa7db4e9fa7db4e9fa7db495b3b4f48633b5348109b0b321b510d3217a18cbf4f9b0b33036bd5d741d785981eac0b066a3a0c819fa7db4e9fa7db49533b4f49d7a15bfe92e9bfc598278b42e18c }

condition:
	$a0
}

        
