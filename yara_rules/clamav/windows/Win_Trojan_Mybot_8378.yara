rule Win_Trojan_Mybot_8378
{
strings:
	$a0 = { 52d09e25debc81eec845418b1e57802645bb5387e24c2b7d3a7c12e1baf666525436bbf7ca59a9f98b2ecd1190af028f32ca0a3025db4751270fdae35fff20baa633e25b209eadbf5aade5778827ce2e29a67ad0e9 }

condition:
	$a0
}

        
