rule Win_Trojan_Trojan_599
{
strings:
	$a0 = { 2e5c2e626174[0-9]64656c202f4620222e5c257322[0-88]6f70656e }
	$a1 = { 696578706c6f72652e657865[0-44]6462786472762e646c6c }

condition:
	$a0 and $a1
}

        
