rule Win_Trojan_JS_170
{
strings:
	$a0 = { 2b207368656c6c3b[0-1]7768696c65287061796c6f61642e6c656e677468203c2030783830303029 }

condition:
	$a0
}

        