rule Win_Dropper_Agent_34133
{
strings:
	$a0 = { f692b9fd96e7ad3ecfdf92f785604d5a26cff739520ee700f83e5339d1521db1cc3a2fcdcf0376bea91dc48240a70e63f4f331faa9e0cae15d047aacf207d246956069ab0dbfa201a3b4d6407e5df42c403ca67cf70da2c3a22618d8a07ae5c1f4b1e7effb7b547e644a195a4167c9d9d1ebfb0fa84ba5d9 }

condition:
	$a0
}

        
