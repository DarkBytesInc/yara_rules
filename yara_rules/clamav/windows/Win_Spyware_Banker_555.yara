rule Win_Spyware_Banker_555
{
strings:
	$a0 = { caa94130aac5ae9c86a213c9687de64096e72f246ef11a8885341d02615864219ec28e56f4940866153a1281cd292f5bfc4c1ccf25dfe87175755d5f1638c74e31a7c9afb68f673bc65424e0a0945959b7040b1ad469c3603751e8d740801aa713cce6b55fd5d08f257b34543624b78c6f8b87fc420c57122f8d2d61bc2a2f098e43086b2519528f2d8bdbe2a10980ad4c9eb7a8467e }

condition:
	$a0
}

        