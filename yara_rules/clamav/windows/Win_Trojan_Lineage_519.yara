rule Win_Trojan_Lineage_519
{
strings:
	$a0 = { 7e268caf53737aeeb1aaa54652fe4bd83be0f2ebec912c4624d061c31e170eabb034babccf59542118a2dd1dfa8e966f4320466421c1880e373cb521b23dee125537fdca48b9d451b1177d309de97c3406fc68bbe607f508b74cc78af0c070 }

condition:
	$a0
}

        
