rule Win_Trojan_Pakes_246
{
strings:
	$a0 = { 0ab5a1279e54dfb3e122040887c0f3708a01c47aa68d8f418aa9cfef6dab01ca83fac104c3c8f956979402ef079399018e690fcf64580001774eb3edd805078feba4c6e487a9367136a6f742187710d2415903837d170fd94a49c25cb3ca831812a62ef81843403d77ee13fab435a6780a5eab9770129964c31cfaaf96acfae66846afa559a0ceee60259308 }

condition:
	$a0
}

        