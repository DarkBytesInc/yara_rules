rule Win_Trojan_Agent_32826
{
strings:
	$a0 = { a7aa6773e330e193ec0e09dee207d2bdce120355014c0a27d3e2bbe0adeb951a5ea384f6d6ad8a6907cc20a8a8431758e793f5389b51462e8989385a8606ffb6f000bd06eac6f1dd81fd49c8c3c1c8ebd1d780ae68f8853c75ce }

condition:
	$a0
}

        
