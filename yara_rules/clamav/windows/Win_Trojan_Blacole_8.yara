rule Win_Trojan_Blacole_8
{
strings:
	$a0 = { 633c797979677a3d5c69677a383a63693a6769673d67692774663b6a6338693e6463203a633934673a }

condition:
	$a0
}

        
