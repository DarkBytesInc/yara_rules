rule Win_Trojan_Hupigon_178
{
strings:
	$a0 = { c6e71d80223ff8ec9b748b50c5e0be5c6d260bd03ef23986c407bbd6b8462f779c9ca9c6fec8ccd7f53c615f074ca1b158fb9a23b091dafbd82a7ef034cdaa1595a95de3b2bd87cf8db0bbe71b69306aab404dc51752e28e9b0c94cb6e86c05026af35c4b0be520105 }

condition:
	$a0
}

        
