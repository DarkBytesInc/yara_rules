rule Win_Trojan_Mybot_4432
{
strings:
	$a0 = { 266dede88c0b2fac22a5cd0febbe5326e3582996c22d9e6da538ab74c586b3056c11eebc0b975a2a84d3da746f34364f4712ae8ca21b5b33d11727b058ed0cd13cd914a74038804d3e50a513d5e9cb766a0777aea6fe8a2ba6e5c70a1fbb887a861e70065a660d8d15b21e44202a02fd154843d0d020faebac7e03c7dedecf9ef3706679ee357a1f418eb1f6185ed266da5a817e5746 }

condition:
	$a0
}

        