rule Win_Trojan_Hupigon_67
{
strings:
	$a0 = { 97c8c2e34545c960064c7b401a408f2d0e3616be7ef0317add40a933271b252b346e7459456d86d727f109bf612f3844d4b050d088faa4e1b34849676d8f233ebfee93ffc860260937ef65aaa43cec390f5ed5542c60e5e90084498a197bde9c141326d6cb6755bb899804b919c2ac1d80779704425d5f6e76bdc2d5bedcd701410eab8131f485a34219f074490c0ef9551e6d663bb4 }

condition:
	$a0
}

        