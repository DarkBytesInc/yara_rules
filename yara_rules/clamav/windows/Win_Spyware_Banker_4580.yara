rule Win_Spyware_Banker_4580
{
strings:
	$a0 = { aeb2252fd7bfbaaef4eb00eb5b60c224373b23ee7c989b363fd3182d1923322e811a3a346779942de6314be2ce27cd378deae1e797e9e7d29d7bf8c1e38fdee06a94ebd91d1518d97823848b32f729c530f827fd5e250f004b20ff3cd8dbcc59ad6dc26a }

condition:
	$a0
}

        
