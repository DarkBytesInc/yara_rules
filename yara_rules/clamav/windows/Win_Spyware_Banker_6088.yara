rule Win_Spyware_Banker_6088
{
strings:
	$a0 = { e73a284d9acb0ec36cee339e10688ebcc93d5a8e17f05e11a1b801d1582e3bc546a61bc7b9a9987b881c884da431424d8c7fef658c4ac9601d2bd002cd455380aedb5a9a3cdb2c28de84607b010dcdaa42f91a2cc8fd5b76d5c3f71c748625b9bfea39847845fed063c93de7836ff13a7622b932175c1c0109fc8182ad122672d789a86a }

condition:
	$a0
}

        