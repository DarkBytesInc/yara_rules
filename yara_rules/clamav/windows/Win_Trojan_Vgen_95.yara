rule Win_Trojan_Vgen_95
{
strings:
	$a0 = { ff53c0c100f028434f4e20202020205110700170017001760336047001ca04f604f60470017001700170017001 }

condition:
	$a0
}

        