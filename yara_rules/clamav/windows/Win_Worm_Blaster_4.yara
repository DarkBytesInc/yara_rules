rule Win_Worm_Blaster_4
{
strings:
	$a0 = { de131cd0f3ff444c4c484f53542e4558459a14f9eebd85495438530b5061 }

condition:
	$a0
}

        
