rule Win_Trojan_Vampire_2
{
strings:
	$a0 = { 06e1705701a0436c69656e74832256616d70d372d820312e74327753f276d3060d7d6f32dba6b8a6230732220d0a569a }

condition:
	$a0
}

        
