rule Win_Trojan__0313_0002_000_1
{
strings:
	$a0 = { 33c933d2cd21b440b972018d960500cd21e828008d969101b409cd218d967001cd21c3b920 }

condition:
	$a0
}

        
