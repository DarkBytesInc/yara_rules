rule Win_Trojan_Delf_1286
{
strings:
	$a0 = { 4600a483150414647e0ac40a1a044dd903583cce5696dfc5bccef72bf877f01e7733b902def32072dbdd0b7bce40e5abb15eac17aaec05a401bc7202db8096dc906d7246bc72416dcd06b724829900bd7242f5cc8379db9236f79906b6e02f7999cb7f0effffffb7dfef5ebdfbddf3cf7e79efcf9e7cddfdbd7dfd0450c0c1e417ad76bdfed367e0068cf9bf }

condition:
	$a0
}

        