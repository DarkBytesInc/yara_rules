rule Win_Trojan_SdBot_1768
{
strings:
	$a0 = { 6c71bca295e649c8f9bf9ce3d16c0098a785870aa068ec39d4410ff4bd4e9ce1cee97a2195f4f5f6edca9791ffaa495aba674343c515d5cbf1d35837f6a6e2855fe6524ae19dab925fe5a9b461600ff606b877e517dd95ccabb9a503f19e50c7c96a }

condition:
	$a0
}

        
