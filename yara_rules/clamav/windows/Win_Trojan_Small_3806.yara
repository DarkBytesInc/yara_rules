rule Win_Trojan_Small_3806
{
strings:
	$a0 = { 66e49ed4e380165877a41548cbb4de5dfe20bad172a49efc3fb4de5dfe28bad972a49ed67ae48e1d772fa30967e49ed4e380e25877a41548d7b5de5dfe20badd72a49efcb3b4de5dfe28bacd72a49ed67ae88f1d772d0a79eba19e5dfe20bafd72a49ed0e1ec9b5d772d1279efa19e5dfca95e }

condition:
	$a0
}

        
