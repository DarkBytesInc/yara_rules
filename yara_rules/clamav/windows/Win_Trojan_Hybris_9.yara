rule Win_Trojan_Hybris_9
{
strings:
	$a0 = { f882675aced6540b1ca2cbe8f9d9f7f5b80c6e7cae50a8411a617eac2ca75850dfe84d31d90549a95291ba406b828d57ce14c6ed774a0e36327d0e37cb5f9c5fd00a28e4d75700e95cbc67a073115a55e63b7e980f3062bcee0487b1809da25ca34cfd15fa8f62c4f4bf8f60babb }

condition:
	$a0
}

        
