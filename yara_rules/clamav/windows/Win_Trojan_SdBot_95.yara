rule Win_Trojan_SdBot_95
{
strings:
	$a0 = { de7ef0dd1ff1e5a8b3eec01c7bbb1f60cbc1bbfb5cbd64bb7189db123ba6f4bdf2b3db8cdb743bfe12bd5173c3426f82ec63c4f65bcfcc7267ccfcfdbb92c5cbdd6d945e7cdd8f70edf0ddd31ddc4a6f74ef36c4ca7c751db78cc969067097060cb407dd359dc7e9f63ff66eacef426667c0cf23f359d6bdcd5f670439970028bc3009bbdf97d9725f9d4e6bb5575e67fe2c5b81ffb6 }

condition:
	$a0
}

        