rule Win_Trojan_Robobot_189
{
strings:
	$a0 = { d5ae6cc2236ba89412ba790d28408bc7c16a233394314f742a0d5ff2c189400a6a2fa6b7fdb06c64d7125373d2afe8057ae7377ce691fdaa620273965ac4d883785f3453210ca8735cef013f52227b9398ab6a2ae9752e9f5cc707363d19affd8839df09ced97ede5e4c36b7d34c9d46287d38cb5330011a24f7013f857e4d9d29497adf1d0c18c23889dcf15b18446e41dc0c9c529d }

condition:
	$a0
}

        