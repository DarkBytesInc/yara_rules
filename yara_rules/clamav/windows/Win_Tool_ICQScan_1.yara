rule Win_Tool_ICQScan_1
{
strings:
	$a0 = { 696371706f727400506f72745363616e000058706f72747363616e00 }

condition:
	$a0
}

        
