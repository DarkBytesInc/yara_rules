rule Win_Trojan_Squatter_1
{
strings:
	$a0 = { 8bec5e3976000f8523011e06b430cd213c05cd030f82d7012e8b840a002e2b8416002d423ecd2f2e8aa40b0080ec053ac4cd037548b81043cd2f2e899c5a022e8c845c02b410baffff }

condition:
	$a0
}

        
