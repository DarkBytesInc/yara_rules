rule Win_Trojan_Quickbrowse_1
{
strings:
	$a0 = { 4252535200000073767272756e2e657865000073767272756e00007162000073767272756e752e6578650077696e64697200005c73767272756e2e6c6f6700696e7374616c6c00756e696e7374616c6c000000696e7374616c6c0073767272756e000000000000ffffffff6d12400085124000000000001d644200e01c4000103340005ec8 }

condition:
	$a0
}

        