rule Win_Worm_Koobface_77
{
strings:
	$a0 = { 68[4-4]8bcb871424438d46??83ef??c20000 }

condition:
	$a0
}

        
