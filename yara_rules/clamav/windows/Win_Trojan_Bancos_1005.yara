rule Win_Trojan_Bancos_1005
{
strings:
	$a0 = { 7326774d0632e833a934584b208d8f8a4a9e9a71713ebebcbbb3166b7d01928a94fadac467226222565653ae275ed0a65afa9120cd9e8548161f6976350669bb }

condition:
	$a0
}

        
