rule Win_Spyware_Banker_2394
{
strings:
	$a0 = { 550bdada22377e6150b9528e7129285077d6f6cbb2e26a1c91955aa584213e12626031554471c4affe74cbfbd3d763ef48efa2d42ecf765cb0459a759fd7f3da2596ae68bcf558c621a686df220d2ac32f83ec1d9a63ba3e991d7255e26cd6564b3c108ba54a73a468d4e4650fa829ddb4d67d3d74765396faa623aa824eca79a5f38c7c3f2b2bbb8ab9d0e36020b7899c00715e }

condition:
	$a0
}

        