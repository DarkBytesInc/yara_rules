rule Win_Trojan_Companion_1
{
strings:
	$a0 = { 35cd21891e64018c066601ba1801b425cd21b299cd2780fc4b75465653515706501e52bf6801578bf20e07acaa0ac075fab456268865fe5fcd217219b43c }

condition:
	$a0
}

        
