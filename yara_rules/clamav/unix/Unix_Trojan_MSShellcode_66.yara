rule Unix_Trojan_MSShellcode_66
{
strings:
	$a0 = { 31dbf7e35343536a02b06689e1cd80975b680a074dba680200115c89e16a665850515789e143cd80b207b90010000089e3c1eb0cc1e30cb07dcd805b89e199b6 }

condition:
	$a0
}

        
