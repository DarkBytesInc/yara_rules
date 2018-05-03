rule Unix_Tool_13435_1
{
strings:
	$a0 = { eb315e89764f8d5e08895e538d5e0b895e5731c088460788460a88464e89465bb00b89f38d4e4f8d565bcd8031db89d8 }

condition:
	$a0
}

        
