rule Win_Trojan_Agent_35218
{
strings:
	$a0 = { 210668911d6730c5a9d86f24e46a0495faad4827edee96cca44a419c88d0b6ce6c7e16fd079f01442cea360df96579d31cc13f5fa9770afbd3231a816662037dc1037a0523c6a9c9b537e7cc3d348cb34efebdb5a841dc32d8ec }

condition:
	$a0
}

        
