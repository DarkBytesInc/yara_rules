rule Win_Trojan_Hupigon_981
{
strings:
	$a0 = { aac96dc7bc7ad99654da0c630fcc3818b1040a7d6551c56e3db4c5d04514c37c068ec1edc9253238013e529861a62bbb374c28f2591ed5b1bb02068e837c9991e46db7cedd07bd6bf93f6d17148677480f4b7bbe11bfc3bd44ff8d1a32baeee00946 }

condition:
	$a0
}

        
