rule Win_Adware_Domaiq_1
{
strings:
	$a0 = { 5045467864576c46625842705a5870685257785159586c736232466b50673d3d }

condition:
	$a0
}

        
