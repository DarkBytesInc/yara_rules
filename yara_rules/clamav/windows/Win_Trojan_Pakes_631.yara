rule Win_Trojan_Pakes_631
{
strings:
	$a0 = { 7d088319f9d35c4db882283902f07890fd24688a2121ad00fd0c6d115c0b237bd63c623c96ec3aaef213403682129b2309cd2c5633682440d2e09037af392396de18645c020d3491111a75e26fc6515318dd40a2cc292b283d6d62c426eea8e985190c0a6f62e4e4d240580b238986887dd18869679699dc96903a51f10b385e5f7a8b9f30106c363799af39 }

condition:
	$a0
}

        