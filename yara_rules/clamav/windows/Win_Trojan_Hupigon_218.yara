rule Win_Trojan_Hupigon_218
{
strings:
	$a0 = { fb2896dca595fc916079c76b1d329ca7135d5aaa227da76305d6b759e9c01d1e09d53e05ca6c0aef5de466978835ce2cca6396e503f54dc3ad18dcc6d5ae07107f163b4dc9b16864d62377df6ad0febcec980f51205d38ea8d23d785da2d7e591d41ce8e72aad29ea766f4eea3c7 }

condition:
	$a0
}

        
