rule Win_Trojan_Hupigon_292
{
strings:
	$a0 = { 18f2811affffffff1e19b52bfa987924b05fdf1046d56e582b882d48b4a584973bb4e97f44666ce2ffffffff37d5d9942902cad656d1e519f6b539327086e903ae323f84067b8f5a87c87cbaff3ffeffec326461afafa3668b2b1c4cf744e0c381f75250eee3271ca8 }

condition:
	$a0
}

        
