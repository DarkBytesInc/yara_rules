rule Win_Trojan_Ciadoor_48
{
strings:
	$a0 = { 3afd3a8f51c0f0fa2e73cceac9fee921633dab32e2b57571b62b5213620458957d33b105250499a3bf3941cf710cf6edb7f7a237c867c1b63a93e9b604df93e9d59de25f0b4ec1c4cafaa17267be84bc3db920afe5cad1162f }

condition:
	$a0
}

        
