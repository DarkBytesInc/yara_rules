rule Win_Trojan_Hupigon_1226
{
strings:
	$a0 = { 743214139032141307544f626a656374ff2570f114138bc0ff256cf114138bc0ff2568f114138bc0ff2564f114138bc0ff2560f114138bc0ff255cf114138bc0ff2558f114138bc0ff2554f114138bc0ff2550f114138bc0ff254cf114138bc0ff2548f114138bc0ff2544f114138bc0ff2584f114138bc0ff2540f114138bc0ff2580f114138bc0ff253cf1 }

condition:
	$a0
}

        