rule Win_Spyware_Banker_5897
{
strings:
	$a0 = { 00d18887a93f49ade2c9dfb9f0b0a558470f29a63b8a1da603a8f47c1a7021852500000000270a3fcf09b953719f960c534dca3ff8e548a39a9b32c24ec05ca885dcf4a958000000000b3ca53e6c229431d5f590e04d4623f29ed37e595c256d32a800d39cba99069e00000000b42945d6142abf492cd340db0510e92661f2132025acffedfe2214b14290ec }

condition:
	$a0
}

        