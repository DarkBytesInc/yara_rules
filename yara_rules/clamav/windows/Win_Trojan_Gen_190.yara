rule Win_Trojan_Gen_190
{
strings:
	$a0 = { 1fedf8096869746f68616e6120202d2073fe10f36b617275206261f66f3ee0f6206e69206bf2ea656ff1742e007a78fefc63fdf809fc630d06f9 }

condition:
	$a0
}

        
