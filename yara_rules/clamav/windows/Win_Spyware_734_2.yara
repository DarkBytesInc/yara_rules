rule Win_Spyware_734_2
{
strings:
	$a0 = { 6601d86611fa6659665b665f665e8d4dc8bad02d1413b8e82d1413e866f1ffff8b45c88d4dccbad02d1413e8e6f0ffff8b55cc8d4dd0a1b0461413e862f3ffff8b55d0b8b0461413e84de9ffffb8b0461413e84fecffffe8eef4ffff33c0 }

condition:
	$a0
}

        
