rule Win_Spyware_ot_66
{
strings:
	$a0 = { 68612a83c7cb6e05044c53026565f263effdb975c9b2fbd557ec7bc333c1333d31dd599ea43414f026b50f2a1da6206696449e9ffc8d31af50ff7b41aec2ea1ff5ffe90c2c65b6861c2eaf4381850f5d999db3cc4bfb8862ad0e559eb77b5fceec87d8ee }

condition:
	$a0
}

        
