rule Doc_Trojan_Marker_8
{
strings:
	$a0 = { 436f6e737420657869203d20226c61206d6163726f20646520636f6c6f6d6269612078786122 }

condition:
	$a0
}

        
