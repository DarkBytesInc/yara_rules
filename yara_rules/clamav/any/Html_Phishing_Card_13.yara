rule Html_Phishing_Card_13
{
strings:
	$a0 = { 652063616e6e6f74203c62723e67756172616e7465652073746f6c656e206d6f6e65792072657061796d656e742e203c62723e7468616e6b20796f7520666f7220796f757220617474656e74696f6e2e203c62723e3c62723e3c62723e636c69636b203c612068[0-100]223e686572653c2f613e616e64207570646174652079 }

condition:
	$a0
}

        