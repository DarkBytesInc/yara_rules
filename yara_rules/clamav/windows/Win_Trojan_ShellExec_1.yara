rule Win_Trojan_ShellExec_1
{
strings:
	$a0 = { 69662866756e6374696f6e5f657869737473282765786563272929[0-30]406578656328[0-50]69662866756e6374696f6e5f65786973747328277368656c6c5f65786563272929[0-30]407368656c6c5f6578656328[0-50]69662866756e6374696f6e5f657869737473282773797374656d272929[0-30]4073797374656d28[0-80]69662866756e6374696f6e5f65786973747328277061737374687275272929[0-30]40706173737468727528 }

condition:
	$a0
}

        