rule Win_Trojan_Tiddler_1
{
strings:
	$a0 = { bb007c8bf3bf0103eb3201010002e000400bf00900120002000ae4751260060e07b801038bd8b90100b600cd400761 }

condition:
	$a0
}

        
