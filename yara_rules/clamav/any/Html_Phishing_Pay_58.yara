rule Html_Phishing_Pay_58
{
strings:
	$a0 = { 6163636f756e7420616e6420706572666f726d20746865207374657073206e656365737361727920746f20726573746f726520796f7572206163636f756e742061636365737320617320736f6f6e20617320706f737369626c65206f7220636c69636b2062656c6c6f77 }

condition:
	$a0
}

        