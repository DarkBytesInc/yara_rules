rule Win_Trojan_Delf_1666
{
strings:
	$a0 = { 1da603a8f47c1a70218525270a3fcf09b953719f960c534dca3ff8e548a39a9b32c24ec05ca885dcf4a9580b3ca59eadcf3284c219ad455570e4595b102692ea9d9ca8c6146d297e9150f7d70ac28b8f04f06db20418ff26143b9b820e76c3fae76af3ac86600acaaa700d18fc7a9b9da713205d4eedeefa16363986117e6435c801b90b96534e9a3635b974 }

condition:
	$a0
}

        