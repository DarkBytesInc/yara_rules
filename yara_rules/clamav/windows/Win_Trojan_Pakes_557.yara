rule Win_Trojan_Pakes_557
{
strings:
	$a0 = { 19fff1859554343154851e659ee8c7f099a1def6fd15a4a09909e46d380d1223b2bad06472eb09d28e14116a1e15ea5ba549244acf601260ae5680674bb01b0aba0edd449e090deded0ecc9e0b41234bf45910dea89f2358d969d0bc02eb9795211005760b655299aeb62e73ff7d7cf8194878154394e9c47287082d8d0c09423b7083ffcc08e56ad38d9f65 }

condition:
	$a0
}

        