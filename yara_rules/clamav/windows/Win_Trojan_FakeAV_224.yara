rule Win_Trojan_FakeAV_224
{
strings:
	$a0 = { 69ffe5b083ffe6b288ffecbca1ffedbea5ffeebfadffeebdabffe9a694ffe7a08effe07e6cffe07866ffd95e47ffd95b43ffd44d2fffd34a2bffd14320ffd1421fffd2431fffd34522ffd08b7cffd4ada5ff3c3c3c901f1f1f5a57575704a2a2a202ffffff01ffffff01bfbfbf1c8a8a8a31e2d3c4ffe1c6aaff }

condition:
	$a0
}

        
