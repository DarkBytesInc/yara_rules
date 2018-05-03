rule Win_Proxy_Lager_37
{
strings:
	$a0 = { ac6126d7f26c087cf4697615c8666e620bbb4a69701bb316134bfe53156411e09f1d9e8ce60b8b17243b00e545fec2c11473c6c71dfd8259f18ee45cc3a5cd083b4bfdcd0839 }

condition:
	$a0
}

        
