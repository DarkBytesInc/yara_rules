rule Win_Trojan_Hupigon_1009
{
strings:
	$a0 = { ac92aa5c61658333ce8d09cb4d3f83a5b588eff678cbcb331c318545b56d3574ebc5d3421d7ab51d07f231b8ca68e546a323375e0e1a183349454dcc23b50fa0e05edad2d797bc41e9a40e43dbd2ce1091a47d02ab7229fdd1d257dcb87cb950fdca1bad700d7718c3 }

condition:
	$a0
}

        
