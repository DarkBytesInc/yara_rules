rule Win_Trojan_Lineage_239
{
strings:
	$a0 = { 2ebafd5cd6078b6800c3dd3890d078abcab48a7e2f5b706da805711a41df64a1c26382cca2a854eb006879481d53201a412ca810c8ea511f6b34fcbb10fffc419609cdae324c347d04d07ce2cca9f8f07f80c7da49bacbfbfd7b35a7b0ecce9b2cb77ed53bc00ebf }

condition:
	$a0
}

        
