rule Win_Trojan_Vatos_1
{
strings:
	$a0 = { 68784647008d9528feffffb801000000e81906f8f0ffb528feffff689c4647008b049eff30e8190537d88bd08d8524feffffe8190038b0ffb524feffff68a84647008d852cfeffffba05000000e819003a388b952cfeffff8bc78b08ff5138 }

condition:
	$a0
}

        
