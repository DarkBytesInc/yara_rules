rule Win_Spyware_Banker_1012
{
strings:
	$a0 = { 1a66afaf5897d438801ebcee0d50964e6a0a0094eb66ed98a1f77b3db01b8fe10e4335e01d3c6ac75e560d871df55fedd2e585f789d459d039087db79824e74b129b8506b16689a08a11623cbec523fb3c66de113bbcff4d93ee45bc7af1b3a0c37a06b7db7adf1b28de6d75fb07e62f609ae86da6b2a1de99e4a5ccda7143f231083db8bda468b8b1579a34a19e1af31e08380e884e }

condition:
	$a0
}

        