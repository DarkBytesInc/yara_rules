rule Html_Phishing_Auction_157
{
strings:
	$a0 = { 61732070617274206f66206f7572207365637572697479206d656173757265732c20776520726567756c61726c792073637265656e20616374697669747920696e2074686520[0-20]73797374656d2e20647572696e67206120726563656e742073637265656e696e672c207765206e6f746963656420616e20697373756520726567 }

condition:
	$a0
}

        