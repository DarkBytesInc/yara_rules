rule Win_Spyware_61_3
{
strings:
	$a0 = { 5cd3e8816771b98bc5dceb56de55da517308076441177da98c3b02f565fa23e8e0e5c73afbf22f686b9ebdc6ff9496974e9de20cc87918798458609c85075a494bcb8797acd11c854e514e6b5944251bb67f2812a26c8c01060c8c420ceddf9d7217 }

condition:
	$a0
}

        