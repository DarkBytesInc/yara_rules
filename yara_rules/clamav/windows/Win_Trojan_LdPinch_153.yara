rule Win_Trojan_LdPinch_153
{
strings:
	$a0 = { f585bcc8b8454320364385cf4d1977a783ce9fa3e1b7fdd6529db01fea7edb4fa8e7d765bf185cf474b7c1c5ef142149eb512bc6c0a9743ca481ec3a1f04f5952d7c72ce8407effdcb23b6dd4b69edb7e196694dcf600c00d5fcddae80005043bbd4c1c0e116b2090ff83cf060fdf785768e7eefeb5ab4c0e4fc0e5721f6bc893bc870ae6b8c0decbf2139db }

condition:
	$a0
}

        