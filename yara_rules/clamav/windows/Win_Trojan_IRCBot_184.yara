rule Win_Trojan_IRCBot_184
{
strings:
	$a0 = { ddca7362729f27e627cc79387c74d558d2a303d52627eb10d15cfbc196718f48240d18949fe455c1a74f0e1e153b765b73fd993a3226c9c6c548095650c15cce12a04650c9df335b899626e4b4080589c9a2498866aab07e7633589a7897ef2df2939a077d3b8229e72cad4cae401dbd2dd435a486c70dd72f3b285ea5e1a2e39c0205f20742fd6fb37c2018d404daee2b0a6ffd981f }

condition:
	$a0
}

        