rule Win_Trojan_Prorat_105
{
strings:
	$a0 = { abb8c731c912f015b045d6aa400b5e6d71aadddf83f00a6942733bfc050cbe2ac8d174f74abeca244536a6b3c7bddbb7c3669478fce9a2459dc3bd2a0eb0d3322bbfa860a8ef06c1bd23cb76f25b917a2e7cd24834fdb1eeaeb15b9e8a60d19fa0ea3a3664e4c6d75a95af21b25749b461ec731f80df }

condition:
	$a0
}

        
