rule Win_Worm_Noon_1
{
strings:
	$a0 = { 6c65735c4e6f6f6e65722e76627322290d0a2020206346696c652e436f70792822633a5c4d7920446f63756d656e74735c4e6f6f6e65722e76627322290d0a20202020200d0a202020536574204f75746c6f6f6b41203d204372656174654f626a65637428224f75746c6f6f6b2e }

condition:
	$a0
}

        