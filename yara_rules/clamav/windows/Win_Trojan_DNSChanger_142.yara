rule Win_Trojan_DNSChanger_142
{
strings:
	$a0 = { 1de6f608e3e16d3515b37e6b64363b3eaff979017b7cb0bd673ab44253547ebd2d438af768bf7db61cba7281675475bd3db37efceb7e7f673834383e972f613368bff8f6673b973668bffef16c367eb5abbbf639ed7608f1e3c285bd3db3fef07c3c4336 }

condition:
	$a0
}

        
