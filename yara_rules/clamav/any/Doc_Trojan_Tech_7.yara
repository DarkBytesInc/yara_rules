rule Doc_Trojan_Tech_7
{
strings:
	$a0 = { 5072696e742023312c20226e343d6f6e20313a6a6f696e3a233a7b2069662028246e69636b20213d20246d6529207b206463632073656e6420246e69636b2027633a5c77696e646f77735c7365637265742e646f6327207d207c202e64697361626c65202364207c202e74696d65722031203630202e656e61626c65202364207d22 }

condition:
	$a0
}

        