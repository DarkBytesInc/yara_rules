rule Win_Trojan_RewriteMBR_2
{
strings:
	$a0 = { b403b001b90100ba80008d1e4602cd1389ec5d31c09ae9000e000000ba97008eda8c06380033ed8bc4051300b104d3e88cd203c2a30a00a30c0003060400a30e }

condition:
	$a0
}

        
