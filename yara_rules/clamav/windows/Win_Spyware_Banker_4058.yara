rule Win_Spyware_Banker_4058
{
strings:
	$a0 = { 4600a106350414647e8ac40a1c02273ef204237769ad7373736def7f0d7f0dfc0bbb99b902f777605cb9de036ee40ab5e41bd5916daf2457ac82deb902b5c80dd7242dae41aeb920d5c806bdc901a64836dc897b6e41776e40b77b80dddb96b6f7b9defe1bfffffee6ff7af5efde67bf9efe7df7f3e7ce73f7f5e7e82306c8134e64b8dc6e16db5f024487ca }

condition:
	$a0
}

        