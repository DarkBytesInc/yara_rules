rule Win_Trojan_Unicode_208_81_166_139_1
{
strings:
	$a0 = { 3200300038002e00380031002e003100360036002e003100330039 }

condition:
	$a0
}

        
