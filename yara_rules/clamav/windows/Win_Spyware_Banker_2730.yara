rule Win_Spyware_Banker_2730
{
strings:
	$a0 = { 4eca45bc51aad96d78c4874f9675e75303579025bb4c9ab3c99c44400b1fbf0ef95aa4315a26191279dcc1b0aa0a67bdd78116830de2bce9f559023b6ee0be177b47187293a2a83d6c0223e882da }

condition:
	$a0
}

        
