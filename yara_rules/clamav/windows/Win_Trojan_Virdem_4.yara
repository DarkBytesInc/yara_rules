rule Win_Trojan_Virdem_4
{
strings:
	$a0 = { bc00fe505351525556571e06169cbe80008d3e8203b92000f3a4b80000be5203268904bedd03268a1c80fb397402fec3bedd0326881cb419cd21bea403 }

condition:
	$a0
}

        
