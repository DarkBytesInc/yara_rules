rule Win_Trojan_Delf_1992
{
strings:
	$a0 = { 2b88d081f23e1827d4664f2e825915c9eece8f8228c38a0462139a251617ebf286f080ccf282a2ee400da982547e483064ed7a70dbc408e13d292e11d535f37e8e63d011a4dde86385b03d68e46568a17e5eafbefcd87a9289806666 }

condition:
	$a0
}

        