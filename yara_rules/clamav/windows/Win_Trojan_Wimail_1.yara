rule Win_Trojan_Wimail_1
{
strings:
	$a0 = { 1564020b35002d3d596f752068617665206a757374206265656e204d41494c424f4d42454420627920577972764d61696c202076312e303d2d0d0a0012030017ff1802ff034c000000090b00757365727375626a6563740002047800b004241520010b27004c65742773207461 }

condition:
	$a0
}

        