rule Win_Trojan_Small_3922
{
strings:
	$a0 = { edc519c851bc49ebdfb8494c9eba1456f868f1fde89ab4324ef03bf71231487c8adbcd68901fbffe8de71cc6d363c3fe8d6749d85f5243d9027328039b67befecdea0bfb90c57fe890eb887399d1c6b68e67bebeec }

condition:
	$a0
}

        
