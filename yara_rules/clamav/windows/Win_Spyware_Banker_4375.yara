rule Win_Spyware_Banker_4375
{
strings:
	$a0 = { 41626be6c411e3a8c23769f98410021038781489cedd951c6afbb9126f24bf66e3ad8e1c65af5861ed9b2c7ae71bc821bf8a618c15082f0ec2c8dede6eb3df7e2c41cbad124ad08a039f9feeb197d4a18f87e5cbae1712a8d8dc23dc3d95945902ad3aee42db3c3e13c8669b5ac4fdfc23f96a1d81ef5359b08ee0a29c07637b0936fec2bc02b35c5032928f }

condition:
	$a0
}

        