rule Win_Worm_Nahata_1
{
strings:
	$a0 = { 770f633a5c0054454d500b275662732e4eff03fda52f686120437265714279205b4b69701804fad9725d172d596f75d4 }

condition:
	$a0
}

        
