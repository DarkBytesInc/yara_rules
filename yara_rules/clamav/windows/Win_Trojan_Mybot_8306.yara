rule Win_Trojan_Mybot_8306
{
strings:
	$a0 = { adbf7855711ccdc9cd8bc5d7fcb10c544e8b14d9ddcfeb54060206c26669f02a2e223cf21e60554a64eaa09da132362844ea5e5a5eba52b25f8d47e4b1db7276d469f0989c034af41595c0c492bf5bea460a5be59cee0e400d0195f8130e57238afd2119 }

condition:
	$a0
}

        