rule Win_Spyware_SCKeylog_26
{
strings:
	$a0 = { ab7c0d7414c79960cf8f468d68a1014b20db60cb44f62a96e3b01eb0250f3f235b3d28318347193cc31824b11be026b36c42a05b9077483ba4e93db5cafdc2dd73b2dc8b3787cff01e67e7bdf3ddc3cedc61e491a58cc4420c7b268ebc105bded35d64cf381e0c1103c8eafbbeaaee99912daf93b7c77beaeefaeaabaf }

condition:
	$a0
}

        
