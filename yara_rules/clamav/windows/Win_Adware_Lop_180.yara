rule Win_Adware_Lop_180
{
strings:
	$a0 = { 77234e009a1bfe44533d5db607c986c3cbea285c10114fa1ab8e85a94fb95fc0bde4c3a268b817720c68858423b723795d54127cf2219b95423ed20a }

condition:
	$a0
}

        
