rule Win_Trojan_Bancos_1634
{
strings:
	$a0 = { 1b23d5f7794e71cfba87d80aac4276b035e412b77bf9e33ffeac1d878586de0cecd5b21e38c9a22206435d4ded68596f4e5b9046e367f15a49c3379d7c5c40a0374d7d29853ba5e9b4ece4e44c26aa2f057f990fec3b73522db32b07b064eceaad0868dbd7dbb28fd4a28fa785e50529f0f57e9a370a12f706006a29cd1c810d44025082da253e13b7531aaf76dc23200dc8db244cc0 }

condition:
	$a0
}

        