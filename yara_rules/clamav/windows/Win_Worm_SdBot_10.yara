rule Win_Worm_SdBot_10
{
strings:
	$a0 = { 56640d4d65665b3691b28b583baabd9b63bbe71e9e00b72581dc5e5c9cfd03de3f9a0ae4f3c0be729ada5c2354c201418bd543468607c33c6bf50484b7dd0024 }

condition:
	$a0
}

        
