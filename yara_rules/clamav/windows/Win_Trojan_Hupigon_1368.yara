rule Win_Trojan_Hupigon_1368
{
strings:
	$a0 = { a0df2e794a17f7bf7ed5dc2c17c6cfb758a90a510e791ffe8ef1d1fab01d7da571382b05c4d51ddcc8a9bc3bf687fdf6ca4bfcc67319b94bb3b90f58bde1e4d03e10ef7d17c3ddf71252ab93e8c9c875cf86c8aeed8f54a7ff04e3bcb8530dc77f56 }

condition:
	$a0
}

        
