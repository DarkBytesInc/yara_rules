rule Win_Trojan_Spy_99
{
strings:
	$a0 = { e41ea23561ff5b7b58be97bf6f7a582dd32fab3b769f5ffffff60f695e31d15d87341f62b19c70a2b1ed586a34fc38ce2d71fdff8ff0c84feccb2f4429ff33bd5a6b9475aba66594b0fe3c4bffffffbf5f35a129769471b29c0497b1f854432ee43fb734639775df9a6b9ebae95ffffffff6585df3311f67897fbc926184d4db }

condition:
	$a0
}

        
