rule Doc_Trojan_Thus_12
{
strings:
	$a0 = { 2e54797065546578742022c4ebff20f2eee3ee2c20f7f2eee1fb20efeeebedeef1f2fcfe20e7e0f9e8f2e8f2fc20f1e5e1ff20eef220e2e8f0f3f1eee2202d20ede5eee1f5eee4e8ecee20e2e0f820eaeeeceffcfef2e5f020e7e0ebe8f2fc20e1e5f2eeedeeec2c20e7e0e2e0f0e8f2fc20e0f0ece0f2f3f0eee92c }

condition:
	$a0
}

        
