rule Win_Trojan_SdBot_2132
{
strings:
	$a0 = { 912b7e7bcbe1eef762b4b717225fa3f28ed287e69d9f05af07c6f3c6e990c21d37daad9c556195a278cefe65c879918327b4bb869caa59f48f0ac24ce4c448c86fe806e6bead7437326dd25232bb77e62c0cdae696eac32b9b3b }

condition:
	$a0
}

        
