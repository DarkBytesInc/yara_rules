rule Win_Dropper_INService_2
{
strings:
	$a0 = { 50537ef2750b5399ad74ed9ff8ecff35b4d04bddfa0b0deccd99b09802106850fa66ffffcd1cef188d70018a084084c975f96a002bc65017655bdbce57fe11be2a9e561487349cb70e048bf836444cdfedb76fb05959746860f883c0042b1e8c }

condition:
	$a0
}

        
