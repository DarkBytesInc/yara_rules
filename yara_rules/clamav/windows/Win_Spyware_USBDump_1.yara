rule Win_Spyware_USBDump_1
{
strings:
	$a0 = { 62792056616c67617375203c3c[0-4]25732573000000005c[0-23]25633a5c000000002e2e00002e0000002a }

condition:
	$a0
}

        
