rule Win_Spyware_56288_1
{
strings:
	$a0 = { 558bec83ec20c745f8c8464000c745ec00474000c745f4204740008d45f0506a006a0068ee2440006a }

condition:
	$a0
}

        
