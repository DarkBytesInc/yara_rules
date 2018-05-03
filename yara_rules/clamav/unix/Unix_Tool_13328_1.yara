rule Unix_Tool_13328_1
{
strings:
	$a0 = { eb105e31c9b10080740eff00fec975f7eb05e8ebffffff }

condition:
	$a0
}

        
