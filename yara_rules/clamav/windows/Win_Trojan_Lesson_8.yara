rule Win_Trojan_Lesson_8
{
strings:
	$a0 = { 8945152d03008984a501b440b9f000908d940301cd2126c745150000b440b903008d94a401cd21 }

condition:
	$a0
}

        
