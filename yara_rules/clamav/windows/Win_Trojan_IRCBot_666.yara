rule Win_Trojan_IRCBot_666
{
strings:
	$a0 = { bd30e098dbbbcca44e4351fa6d46c767a9cdeafa21b318bd9fdf210c290890c9132a61aa1ac33ade87e986609f5aff6959d86e8e2486a6f2bcdd020bc4d1f66bc395fb24fe4674e27b8657640534f9504eeabc11388924a3ee0f635b101bb5e3ea5458754219c5cd013e54243d20e3eaa8a624849816f0d1 }

condition:
	$a0
}

        