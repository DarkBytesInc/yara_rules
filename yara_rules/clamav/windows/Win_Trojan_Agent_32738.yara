rule Win_Trojan_Agent_32738
{
strings:
	$a0 = { fd27bba95133374c790f9e5cc4318c05d3a6d02189d2cb19bd1ec1809f60a3552fa2ca9b0e3327f4bc2ec90acf8ea7b30834d086b9bf2c6aac13e35e8684de9fd2b9413fae03feaba643eb2064df9f3f8d65676257 }

condition:
	$a0
}

        
