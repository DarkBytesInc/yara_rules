rule Win_Trojan_Bancos_1031
{
strings:
	$a0 = { d0317e28645e47cede7551d06b57bf7222f87cd0f9f9b1aada47a15307c91e9434e9ae3c981e77cd543bf0bf1e769631c3cdb0d49b2f5c299e1fab4321cfbcaccb53852cef09a4890215266e89d33f3085a82e877b }

condition:
	$a0
}

        
