rule Win_Trojan_Prorat_91
{
strings:
	$a0 = { 4a08b14de6575b35b9a866f03cfa391624342146beb738c3621cffe4f5e30d6dbd853e7f649dd873e9662d24458ced9c7721e4c65e6f5a9fa60db341ce05a4edfe834df0cd31fb97020ddcde81e2232d87eb1cca4f07d09b1c82b644c1feb3538e48444e }

condition:
	$a0
}

        
