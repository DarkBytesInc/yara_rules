rule Win_Spyware_Banker_4570
{
strings:
	$a0 = { 416eb1ea8ebed7f477221781d7659ec560b326e4d406ddcb1bc2d4ebecfed36fa813ab36582d5dfe73d26903408be5f76e889c303ff50d3bf428a0ff6fb8ee14dcdebfe8fcffe07b2c2fd79fd4682d7aa4bd86003eadd56e1b21c5836e78a11c7c191b9f }

condition:
	$a0
}

        
