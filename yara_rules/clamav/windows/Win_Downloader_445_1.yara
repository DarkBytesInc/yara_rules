rule Win_Downloader_445_1
{
strings:
	$a0 = { 85f1fcffff0080c286b212c685f0fcffff57c685ecfcffff4980cadac685e9fcffff6180f22db2835583ec088b85b9f9ffff89042480f63680ed9c80ed4a8dbde3fcffff897c240480c903ff153ecf01105d80e9038985c2f8ffff8b85c2f8ffffa36ecd011080c52b }

condition:
	$a0
}

        
