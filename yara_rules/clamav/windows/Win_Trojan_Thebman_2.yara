rule Win_Trojan_Thebman_2
{
strings:
	$a0 = { 690a56697275734e616d65240c6a094d656e754465636179646909696e66697a696572740c6c000064236901690c6c01002467b7800506641d690a56697275734e616d65240c67b88005690169061e6909696e66697a696572740c6c0100642664641d6909696e66697a696572740c6c00001e64 }

condition:
	$a0
}

        