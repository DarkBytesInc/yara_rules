rule Win_Trojan_Fakecodec_10
{
strings:
	$a0 = { 399548feffff7712019538ffffff118554feffff318528ffffff2945d8218500ffffff29d2ff45c02b85f0feffff2b95c0feffff03954cffffff31c0ff8564feffff11858cfeffff11857cffffff119530ffffff21d04031d0ff8568feffffff4dd02185 }

condition:
	$a0
}

        
