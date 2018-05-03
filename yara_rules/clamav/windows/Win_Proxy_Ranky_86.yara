rule Win_Proxy_Ranky_86
{
strings:
	$a0 = { 62d99967f2ec7de9222edff05475c6ab5aeb6abe2e7a42bdb10a676fdcabdffa526b2d070818bbab5d68d7541be6b5a915dc6a567fe5d9787d309b8339c49d9ea9caa634a79549b25aa8cdca4f301ed27b516cd55eb203c32792990879dac42c3ffb2cf81858530b26da08d7dfb47ff9296a1c4158aad6dd660cab }

condition:
	$a0
}

        
