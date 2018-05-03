rule Win_Worm_Creepy_1
{
strings:
	$a0 = { a1d4744400ba284d4400e8d001fcffe8d217fcffa1d474440033d2e8bf01fcffe8c117fcffa1d4744400ba504d4400e8ab01fcffe8ad17fcff }

condition:
	$a0
}

        
