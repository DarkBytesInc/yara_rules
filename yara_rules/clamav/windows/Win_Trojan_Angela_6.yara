rule Win_Trojan_Angela_6
{
strings:
	$a0 = { 5072696e742023322c20226465627567203c20616e67656c612e646c6c203e206e756c22 }

condition:
	$a0
}

        
