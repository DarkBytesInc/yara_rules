rule Win_Trojan_Small_5285
{
strings:
	$a0 = { a907387bafae853a9728fc7bff900728bff8bad377fbef3b7c3cf76d002faf6ba992ee689710fc7bffad074afcf8efb83be0104fdbe0102ef7e8af3ba0a6b260a63bb96c97f8ff3bff92e7c4eac0ff7bffa8102ec3e8af3b7408853b95dbb951ff07fa6fefb8efbe3f8cddb0c2c8ff7bffae10 }

condition:
	$a0
}

        
