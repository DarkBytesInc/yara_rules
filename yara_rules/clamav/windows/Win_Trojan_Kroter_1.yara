rule Win_Trojan_Kroter_1
{
strings:
	$a0 = { 8d9594feffff8b85b0feffffe81da2ffff8b8594feffff8d9598feffffe8989dffff8b8598feffffba88cc4000e8806bffff75248d8590feffff8b8db0feffff8b55fce8a66affff8b9590feffffa148f640008b08ff5134ff0544f640008d85a4feffffe851a0ffff85c07510813d44f6400088130000 }

condition:
	$a0
}

        
