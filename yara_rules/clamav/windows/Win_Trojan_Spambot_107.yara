rule Win_Trojan_Spambot_107
{
strings:
	$a0 = { 44c05a9df0ffe0ffcb47124956e4ae2874f1219f2f4a11f3150a682df41b57ffff0fdffde0b5a8e43e8642f592d41e589e62a389664329ffffffffad57f759646db58eb0eac804b5810a0540315fc9b1d2f572f8624c6bd5bcd6f284ffffff424b28110b7a633de9eb773382fe54 }

condition:
	$a0
}

        
