rule Win_Spyware_Banker_3518
{
strings:
	$a0 = { f4188a056dacbf8014d201f71942e30b2d5c6526a47b31b8e46912b86457366bcf63e5009be8c15eacf27b9a730d3f69de227f69e4e959e07ebf51a53ba7f52a622dcb047d943e4e52da6bfc4bf67c7e3a10ffce2a5c7511fa3c }

condition:
	$a0
}

        
