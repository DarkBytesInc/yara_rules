rule Win_Spyware_692_2
{
strings:
	$a0 = { 63c5dbc13bf343361cbf5252855ed19d626dbd6590463a02cda6f3cfd0dd08735f181dbb9cacfcb1c1e41ba8b65b7410b52de69cad1ce74853b42f82f7dd4a2ab859181e06a0fd54cc266ef9c1a9c00701c578b03abdcd71493b79823a69c3 }

condition:
	$a0
}

        
