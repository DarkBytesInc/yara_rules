rule Win_Trojan_Ghost_8
{
strings:
	$a0 = { c05a595964891068d5ac40008d45fce86388ffffc3e90183ffffebf08bc35e5b8be55dc38d4000558bec83c4f48955f88945fce8c7feffff33c0556829ad400064ff30648920558b45fce8147dffffe82bffffff598845f7e8c6feffff33c05a5959 }

condition:
	$a0
}

        
