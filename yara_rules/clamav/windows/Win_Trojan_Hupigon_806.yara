rule Win_Trojan_Hupigon_806
{
strings:
	$a0 = { c62d3c50b19fecc2b45b30e22d19a8162dccba6527f8d6ca1be95292888bdacf61548102425809e9fb09099744ed15a4812ade103104b5364ead323f2d6def67d36f660efe00206f1ce9ebd6d991088f9edbd28218abb2f591f00721e57446 }

condition:
	$a0
}

        