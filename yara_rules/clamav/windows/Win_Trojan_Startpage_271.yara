rule Win_Trojan_Startpage_271
{
strings:
	$a0 = { 2f77012e713838702e6e372f4f496910de392e2d6ddfb006e16c36ff3ab385b4fd1f29001d664bdf4d69b715d1ae27731a5c909620457805bd15a170 }

condition:
	$a0
}

        
