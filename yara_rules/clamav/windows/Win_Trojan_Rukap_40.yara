rule Win_Trojan_Rukap_40
{
strings:
	$a0 = { aaf22a9e022c81249f8f6e9eb95594164f835b14515ef3c517ff3ebcdd64dcac7e51ca57408e1b9a98db5ede62abb979088df5ad0dd18c6a2f6d2c5a06254ea6a51418a25bd5cc771ce6fb34e61a3579a9482848290b71dad5 }

condition:
	$a0
}

        
