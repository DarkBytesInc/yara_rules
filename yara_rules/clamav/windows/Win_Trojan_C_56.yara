rule Win_Trojan_C_56
{
strings:
	$a0 = { e0f8e5ec20ede5ebe5e3eaeeec20e4e5ebe53a2d29292929290600062fd2cec2c0d0c8d920cfcecccdc820ccc8cad0ced1ced4d22052554c455a5a5a5a5a20464f52455645522121212121210600062bceede820eee4ede820e8e720f2e5f520eaf2ee20f1eee7e4e0e5f220eceef9 }

condition:
	$a0
}

        
