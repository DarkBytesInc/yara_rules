rule Win_Trojan_IRCBot_264
{
strings:
	$a0 = { c47f8eaa59ad2dd2be8daafe9f69d4de97aab08f7908be97aaf20449c6de15aa6d8fc9ca3f19c0768f8cde9e088a2abd6ccac7acea7b0a6b261e915e878fcece472ecab18f6bc4dcb7aa4c97093a1f1c02609feede5f1fca5410608f5724ca54182ed43744aaff8fe9cc3e8c660f87eade1e0e8af00c8e0a9c28aa8f }

condition:
	$a0
}

        
