rule Win_Trojan_Ruf_1
{
strings:
	$a0 = { b2009a0d0050005589e531c09acd02b200e82aff833e5602007508b801009a1601b200833e5602007403e811fc }

condition:
	$a0
}

        
