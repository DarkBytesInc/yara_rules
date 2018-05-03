rule Win_Ircbot_Ale_2
{
strings:
	$a0 = { 7d038cca03d08cc981c1e10951b90100510606b1ff518cd383eb1853b142fc518cd5be340033ff4d8ec58eda4ab108 }

condition:
	$a0
}

        
