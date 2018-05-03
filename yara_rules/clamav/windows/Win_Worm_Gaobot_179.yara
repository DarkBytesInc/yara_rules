rule Win_Worm_Gaobot_179
{
strings:
	$a0 = { 6661614156dbe8b818348c02d0462d41474f424f54180b20e948494a41434b547e4b2a5a53de }

condition:
	$a0
}

        
