rule Win_Trojan_Netbus_47
{
strings:
	$a0 = { e481271001cf9edddfdc98b6bbb3b4bad2d201c00a03c383a5afb1a4c4ebccc8d9368111568394b5b4fbdfc4184d2c12c9c8af2759892f0c01dc2961e49fd8e0986170636e1dd4490860c2d1eaf6e781835d1909a0147b3110070385011ac866f1e442168ee0565d092d32984312c37e0078b5600cfa34a809aca649e2 }

condition:
	$a0
}

        