rule Win_Trojan_Peed_152
{
strings:
	$a0 = { f7db87da75705589e55389e38d61045089dc5b89d88b5d086bdb0383eb0bc9c20400f7db29dff7db01de89c3eb6889e00110c3ba0400000087d1586866340200ff156850400068000000016a00f764240483c408e82200000089daf7da01d0ba22000000 }

condition:
	$a0
}

        