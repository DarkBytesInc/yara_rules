rule Html_Trojan_VBSNazbug_1
{
strings:
	$a0 = { 013e3906e402741fb84231c931d2cd21b440ba01b9e401cd21b4403e8b0e9abae402cd21b43ffecccd21e9afffb84ccd212a2e7662734e617a627572672062 }

condition:
	$a0
}

        
