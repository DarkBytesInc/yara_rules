rule Win_Spyware_Banker_4553
{
strings:
	$a0 = { 2eacdadaa746e60da26c5e30dc1913c48ca04d178d57595eb98aeb4715cf6c048e44dc980bdd3c0ad3bece93ebc2baf3f4c3489991d14a780e3f06d1a0b19bc98e3293d3b6abeb5df97ec7c7382d052b4281a7a0bd49fede6b85fe3d0326c39f2f77eef4 }

condition:
	$a0
}

        
