rule Win_Trojan_Hupigon_1682
{
strings:
	$a0 = { c6bf72824ed81856b5ccd068ee05b1ccbd2202146a08ff5bb63a3d51a8be88583f982b1de5c1871f33da01ae26fb59240ab05887e2f48697da0e9e26d3c61ebb4cda236a16c4d8fc11afc5b98543d46c2e5734463b30b2b4be01592dd790ab }

condition:
	$a0
}

        
