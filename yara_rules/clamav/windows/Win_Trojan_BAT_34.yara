rule Win_Trojan_BAT_34
{
strings:
	$a0 = { 455420504154483d433a5c746f6f6c3b633a5c646f733b2550415448250d0a7374617274202f6d20666f726d617420633a202f71202f6175746f74657374202f750d0a7374617274202f6d20666f726d617420643a202f71202f6175746f74657374202f750d0a7374617274202f6d20666f726d617420663a202f71202f6175746f74657374202f75 }

condition:
	$a0
}

        