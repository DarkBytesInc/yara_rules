rule Win_Worm_Hlux_2
{
strings:
	$a0 = { 8bff6a245960befc1f4000f3acad0fb6002c680f8483030000c300008bff55bb0000000053e88205 }

condition:
	$a0
}

        
