rule Win_Trojan_Mybot_8188
{
strings:
	$a0 = { 764399030e1244acffa1e19969aba6ab386ff616fd36ea049e0304c1b959fa1e33b850947fe6e9efdc8abd36bfbf778a5d0d896561be9f5a84b1f809cadb4836d1bdb8ce92e8f24ccbd0e06e94d53a38deab589941f614185a2ec5f58b44e5cd166146ffd07ccf7aa091fe2d47fbe1fcbd0ff2c1eb60b592 }

condition:
	$a0
}

        
