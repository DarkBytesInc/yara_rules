rule Win_Spyware_Banker_5500
{
strings:
	$a0 = { d600e7c42290eb1c7d8a0f2b66577b99e9f928e94535af6dd9ab74462f9ab770c3dfd8815f9717a5d1ddef0c51d6ff070444b8e1ee951bc4440d80827dfe531534eff9bab59ac2720573083ec3c9aef6504681c217d28764781172380e13bb6487dace4f7c79fc54322a3c8fc501074470dbf3435467c7b1d8bfb03f5aeb08ae1726efff3d77b5e32c2ad9e3c82315c2702b01194601 }

condition:
	$a0
}

        