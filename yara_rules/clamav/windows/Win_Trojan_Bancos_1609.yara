rule Win_Trojan_Bancos_1609
{
strings:
	$a0 = { 470f29a63b8a1da603a8f47c1a70218525270a3fcf09b953719f960c534dca3ff8e548a39a9b32c24ec05ca885dcf4a9580b3ca59eadcf3284c219ad459ced9f06c1ffffcfd6438772d1c6bd7f7cad19eda242ded6d358acbcea92ba2607855edb869be593473bf99b42f52ab270657011880ad6fbc84fdb5daf1c98411126cad49b17dd6859a2f082b2fc28 }

condition:
	$a0
}

        