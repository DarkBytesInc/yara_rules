rule Win_Trojan_MsShared_1
{
strings:
	$a0 = { 64726976657273[1]74616e636875616e67[3]756e696e7374[2]636d64[1]7063696e666f[18]4d5942414259 }

condition:
	$a0
}

        
