rule Win_Trojan_Bancos_1446
{
strings:
	$a0 = { c1ca3bec47eedd50dc399e08afef7237c57fbbf66cadcfde216c8deb5d57e77384565e2a8f0b44109d7d77b927e16ec9d3d8eded5f0871fa533f78a98a30473875693a30f84383ec78831691fde3690bfc5ca74e97c68377e0390c79ef1ae41d }

condition:
	$a0
}

        
