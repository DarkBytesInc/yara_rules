rule Win_Trojan_FakeAV_206
{
strings:
	$a0 = { 558bec81ec2c01000083a55cffffff008bcd118d5cffffffd9f02bc0c78560ffffff000000002b8560ffffff8b8d60ffffff83e000fc53c78540ffffff00000000f78540ffffff6dc700007774b9c6650000ff8d5cffffffba7165000089953cffffff1b953cffffffc78564ffffff6dd40000b8711b0000098564ffffff2bc9 }

condition:
	$a0
}

        
