rule Win_Spyware_Banker_3375
{
strings:
	$a0 = { 661d1757c7d9feaef25865b7e06ed4cb9c5c81bab5943c13b5f9a315e7765866aede2793dce823a0f45e3b1544e373a6071f2abbfd1f4b360c08e67d2fec9c8800d96d818d5abe33a6417cbdf9912fe422b36e43d8 }

condition:
	$a0
}

        
