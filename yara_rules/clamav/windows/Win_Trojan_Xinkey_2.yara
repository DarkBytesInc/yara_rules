rule Win_Trojan_Xinkey_2
{
strings:
	$a0 = { 5ba6c82634b3e33cfbf77798598e72960b3e5c09433169ec7aff1dae38457626e99984e639b762bdce3bdc9418a23d8496f215f34a1b5ee00a1b9053f459db3d078be3e50d3341c57a22f716dfd8820b2fc15e4eddbf733e5a2ac11a29276b1ea74f9682e7dc0f4776e7e6dd206f0ee70cb2151354aead72cb697c }

condition:
	$a0
}

        