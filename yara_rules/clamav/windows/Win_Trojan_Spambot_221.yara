rule Win_Trojan_Spambot_221
{
strings:
	$a0 = { ba80c0b6f4347094770a34a4955a81b351f8ffffd148b0fdef322d691f8bbd54bf90a3f5fea97af963b96a657ffaff7f6375279a32f1c3fa7d397dad756cbc59f7e965c67b6e7bf5ff07f8e9f5502d7b5d1a5fad2737c7c2d38bf5e1f70aff3ffc7f35643cb36fbb298abfceec48 }

condition:
	$a0
}

        
