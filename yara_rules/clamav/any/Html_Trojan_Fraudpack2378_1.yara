rule Html_Trojan_Fraudpack2378_1
{
strings:
	$a0 = { 558bec518bcd2bcce820000000585a595aff8aac000000750a8182b800000018 }

condition:
	$a0
}

        
