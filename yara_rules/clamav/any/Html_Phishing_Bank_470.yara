rule Html_Phishing_Bank_470
{
strings:
	$a0 = { 776520726563656e746c79206e6f7469636564206f6e65206f72206d6f726520617474656d70747320746f206c6f6720696e[0-3]20796f757220[0-50]66726f6d20[0-2]666f726569676e206970206164[0-1]726573[0-1]20616e64[1-150]7765[1-150]6861766520726561736f6e7320746f2062656c69657665207468617420796f7572206163636f756e7420776173 }

condition:
	$a0
}

        