rule Win_Worm_Blackwhack_1
{
strings:
	$a0 = { 64892033c055687439151364ff306489208b55fc8d8518feffffe858f3feff8d8518feffffe8e9f0feffe81ceefeffbaf83b15138d8518feffffe82c0cffffe8b3f6feffe802eefeff33c05a5959648910 }

condition:
	$a0
}

        
