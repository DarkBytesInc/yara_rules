rule Win_Trojan_SdBot_2292
{
strings:
	$a0 = { d33dcbcece3a77edff835353fd0b05704c668ed4d849bdf833a0f5d0cf4ada5cc5639d0bb43285aa992178cf5e5e719118d2e5fa2e9ee9b928de7c2cc8e2136477bef9262da3df910eb1ca483b769b5a11b445d93b4e02074da7f593b92fc9091f9589 }

condition:
	$a0
}

        
