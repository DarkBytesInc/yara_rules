rule Html_Phishing_Azon_4
{
strings:
	$a0 = { 757370656e6465642c2062757420696620696e20333620686f75727320616674657220796f7520726563656976652074686973206d65737361676520796f7572206163 }
	$a1 = { 6f6c6f723d236363363630303e746f20636f6e6669726d20796f7572206964656e74697479207769746820757320636c69636b20746865206c696e6b2062656c }

condition:
	$a0 and $a1
}

        