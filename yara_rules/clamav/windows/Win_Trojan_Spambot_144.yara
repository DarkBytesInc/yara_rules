rule Win_Trojan_Spambot_144
{
strings:
	$a0 = { ca06ffff9f085df850ce9de361d2f4c735a4dd946eac36a4a8ffbffaff56df238b002f4e02b19a9184411ff6a1606fabdb1aaeccce20f6ffffffffeaa7ce010206c34a80fa8590b170e9546e40a6fd7d4efc002c4cd21bb8e7d052ffffffff47f8f2709e9645d7fa6d62cee460cb }

condition:
	$a0
}

        
