rule Win_Spyware_Banker_1250
{
strings:
	$a0 = { 786f0acfbe91e0bce590a718d310fa012c73d3458a4b3114763ef1c6ed71c178990cf5cbc02de9e67fb4de1e156c8ce85c58cc380ec8c61df096428fc8587fce81a37415bbefdd05f70ee6867f10b75c80d7a7f6dd923ce5623a19ca03d94d7bfe06d2f8 }

condition:
	$a0
}

        
