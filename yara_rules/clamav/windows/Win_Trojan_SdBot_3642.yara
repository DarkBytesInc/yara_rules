rule Win_Trojan_SdBot_3642
{
strings:
	$a0 = { a278122c3fb562d161eb2c07294a522570e65ae6acdd9ce4d80dca378e92052cb3b1ba46c60151e2a126515812a93e96a85df88650e3a74582664b8dcb73ece4e1ef3343a6e90805014c39d6aaee }

condition:
	$a0
}

        
