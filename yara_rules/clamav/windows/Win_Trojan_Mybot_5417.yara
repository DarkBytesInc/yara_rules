rule Win_Trojan_Mybot_5417
{
strings:
	$a0 = { 7fee8da715d6dce8edeaf644b38c854340f14dbd737feecca315d9d735edeaf940afac453f40f0d8dc6f7beeaca315d5d7ddededf93fae0c413f40f0a1d86f7aeda8a311d5d7addfe8f53fae1b213f3bec0dd86e7aed689e10b5d379dfe8f55baa5d603a3becf9986a }

condition:
	$a0
}

        
