rule Win_Trojan_Agent_32834
{
strings:
	$a0 = { 8dc7cc33b5a5ee7ff81c27e0c3889e4b029626f362b9f58f6dd76c9b043e31858599e223c433205b116ff6f461c5e876c6f438b86355c70dda0777d991b8a1708c }

condition:
	$a0
}

        
