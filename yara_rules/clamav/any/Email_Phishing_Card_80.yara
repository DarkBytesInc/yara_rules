rule Email_Phishing_Card_80
{
strings:
	$a0 = { 596f7520617265206164766973656420746f2063686f6f736520616e6420616374206f6e20616e79206f66206f757220636c656172616e6365206f7074696f6e73207468617420776f756c6420656e61626c652074686520636f6d70756c736f727920636c656172616e63652066656573207061796d656e74206265206669727374206d616465 }

condition:
	$a0
}

        