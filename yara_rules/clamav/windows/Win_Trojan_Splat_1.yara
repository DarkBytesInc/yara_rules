rule Win_Trojan_Splat_1
{
strings:
	$a0 = { 01b0a00a060200eebaf201a00400eebaf301a00300eea10000baf401eebaf5018ac4eebaf603b00aeebaf701eca84074fbb030ee8bf3baf701eca80874fbbaf001b90001fc26f36ffe0e040075e8fb071f61c3601e06b40fcd103c03755bb403cd105251e85600e87700e8c9 }

condition:
	$a0
}

        
