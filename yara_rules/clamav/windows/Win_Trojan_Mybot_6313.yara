rule Win_Trojan_Mybot_6313
{
strings:
	$a0 = { 7b648e3ccedb9ad45bc29baddccd331bcc10071e64d26a7561754b44e85dcd8f19764950d5062ae1e7b43e00c2d70618382241fd3da053302bccfa28936f4e8f21a040a0266fcbf41b3527d2c803a78ab7c916e66af14c1bc29c8621062d85e048680e51fe2c0e25ba44362fc2db23f572d50dff7a1a349c3e53c4909b6cf02cc2cbbba0b540a1deb30a68d008acb144c58769753345 }

condition:
	$a0
}

        