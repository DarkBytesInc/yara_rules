rule Win_Spyware_W32_39
{
strings:
	$a0 = { 2fe7a872f1e5dc6d21a1987cc44a354f2a7a2a346e985bac5c236bc378c9758b805ba0c64693cf0d148ecc783dd663f452a050a71259ab57a3002426802218b9 }

condition:
	$a0
}

        
