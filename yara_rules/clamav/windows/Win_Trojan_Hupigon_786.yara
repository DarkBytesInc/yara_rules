rule Win_Trojan_Hupigon_786
{
strings:
	$a0 = { 7c2cb7b4019738209c23c8ddae4929fee5efdb7ef016a61d91e65c23669cc250d4183b8ee1fa273acba0bd7cd2cd046e91fa06fff2365b3a6dc7c11711f4b22fb50f06b4a258be0a63284ff11a4533e303b9d7444932f10c51c89b40a3ad05 }

condition:
	$a0
}

        
