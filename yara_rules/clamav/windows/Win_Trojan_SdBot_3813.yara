rule Win_Trojan_SdBot_3813
{
strings:
	$a0 = { e1bbe99da5264c22d511d3cbbbaafdec24c73b09eb09404d872d6ffa0b7f594336aca7ff1d9beb6722ebb0b05c2ae55116f70a2d31c727637d1e6f26e85d097debd0fefdc73729d41bc5ee9f5b78f059fc7e920f47d8ae1941fb532be3b2e477192d }

condition:
	$a0
}

        
