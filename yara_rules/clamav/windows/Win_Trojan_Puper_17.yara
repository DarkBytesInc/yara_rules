rule Win_Trojan_Puper_17
{
strings:
	$a0 = { 3955c5a67d47c2a56d50bba83924c7736b53ca9f2a58c6af8146c89b0ae555365d59c5a62a35c5a65f55c9565953768f795ac8564d54c3a67f59bba80ae55536 }

condition:
	$a0
}

        
