rule Win_Trojan_Killfiles_59
{
strings:
	$a0 = { 64656c2f462f512f41202553797374656d4472697665255c4e544445544543542e434f4d3e6e756c }

condition:
	$a0
}

        
