rule Win_Trojan_Ace_3
{
strings:
	$a0 = { 6563686f20223c68722f3ed7a23a20d6bbd3d0c3fcc1eed0d0b3ccd0f2d4da434d442e455845d4cbd0d0bbb7beb3cfc2b2c5bfc9d2d4bdf8d0d0c1d9cab1cec4bcfebbd8cfd428c0fbd3c322223e2222b7fbbac5292cc6e4cbfcb3ccd0f2d6bbc4dcd6b4d0d0b2bbc4dcbbd8cfd42e3c62722f3e22 }

condition:
	$a0
}

        
